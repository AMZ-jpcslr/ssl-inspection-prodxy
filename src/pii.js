/*
メモ
PII（個人情報）検出ロジック（プロトタイプ）

- 例として「メールアドレス」を正規表現で抽出する
- URL / リクエスト本文 / レスポンス本文 / フォーム値（multipart含む）から候補を集めてログ用フィールドを作る
- ダッシュボード詳細表示のため、ログエントリから“オンデマンド再スキャン”してサンプルを補完できる

原理（要点）
- PII検出は“収集したテキスト”に対して走るため、本文の収集/デコードは `src/httpBody.js` に依存する。
- 表示時はマスキング（例: `u***@example.com`）し、原文の露出を抑える。
- JSONLの保存フィールドを情報源に再スキャンできるため、過去ログもUIで再現しやすくしている。

このファイルがどこで使われる？（データの流れ）
- `buildEmailPiiFields(...)`:
	- 呼び出し元: `src/main.js` の onResponseEnd
	- 目的: 1通信ぶんのログに「PII検出フラグ/件数/簡易サンプル」を付与する
- `computeEmailMatchesFromLogEntry(entry)`:
	- 呼び出し元: ダッシュボード表示（render.js）
	- 目的: 古いログでも、保存済みのURL/本文/フォーム情報から“再スキャン”して詳細を見られるようにする

注意（限界）
- 正規表現でのメール抽出は完全ではない（誤検出/取りこぼしがあり得る）。
- 本文が「未収集/切り詰め」されている場合、PII検出も不完全になる。
*/

const { URL } = require('node:url');

const { decodeTextBodyForPii } = require('./httpBody');

// ============================================================
// PII detection (prototype): email address detection
// ============================================================
const EMAIL_REGEX = /[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\.[A-Z]{2,63}/gi;

// ============================================================
// PII detection: credit card like number detection (best-effort)
// - Extract digit sequences (allowing spaces/hyphens) and validate with Luhn.
// - This is heuristic; false positives/negatives are possible.
// ============================================================
const CARD_CANDIDATE_REGEX = /[0-9][0-9 \-]{11,30}[0-9]/g;

// ============================================================
// PII detection: Japanese phone number like detection (best-effort)
// - Examples: 090-1234-5678, 03-1234-5678, 0120-123-456, +81-90-1234-5678
// - This is heuristic; false positives/negatives are possible.
// ============================================================
const PHONE_CANDIDATE_REGEX = /(?:\+81[-\s]?(?:\(0\)[-\s]?)?|0)\d{1,4}[-\s]?\d{1,4}[-\s]?\d{3,4}/g;

// 文字列の配列から、ユニークなものを大文字小文字を区別せずに最大limit個まで返す
// - PII候補は同じ値が何度も出るので、重複排除してログ/画面を見やすくする。
function uniqueStringsLimit(items, limit) {
	const out = [];
	const seen = new Set();
	for (const v of items) {
		const s = String(v || '');
		if (!s) continue;
		const key = s.toLowerCase();
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(s);
		if (out.length >= limit) break;
	}
	return out;
}

// テキストからメールアドレスを抽出して、ユニークなものを最大maxMatches個まで返す
// - 正規表現は「プロトタイプ用」の簡易実装（完璧ではない）。
function extractEmails(text, maxMatches) {
	const s = String(text || '');
	if (!s) return [];
	// EMAIL_REGEX はグローバルフラグ付きなので lastIndex を毎回リセットする（前回の検索位置が残るため）。
	const matches = [];
	let m;
	EMAIL_REGEX.lastIndex = 0;
	while ((m = EMAIL_REGEX.exec(s))) {
		matches.push(m[0]);
		if (matches.length >= maxMatches) break;
	}
	return uniqueStringsLimit(matches, maxMatches);
}

function luhnCheck(digits) {
	const s = String(digits || '');
	if (!s || !/^\d+$/.test(s)) return false;
	let sum = 0;
	let alt = false;
	for (let i = s.length - 1; i >= 0; i--) {
		let n = s.charCodeAt(i) - 48;
		if (alt) {
			n *= 2;
			if (n > 9) n -= 9;
		}
		sum += n;
		alt = !alt;
	}
	return sum % 10 === 0;
}

function matchesKnownCardScheme(digits) {
	const s = String(digits || '');
	if (!s || !/^\d+$/.test(s)) return false;
	const len = s.length;
	const p2 = Number(s.slice(0, 2));
	const p3 = Number(s.slice(0, 3));
	const p4 = Number(s.slice(0, 4));

	// Visa: 4, length 13/16/19
	if (s[0] === '4' && (len === 13 || len === 16 || len === 19)) return true;

	// Mastercard: 51-55 or 2221-2720, length 16
	if (len === 16) {
		if (p2 >= 51 && p2 <= 55) return true;
		if (p4 >= 2221 && p4 <= 2720) return true;
	}

	// American Express: 34 or 37, length 15
	if (len === 15 && (p2 === 34 || p2 === 37)) return true;

	// Discover: 6011, 65, 644-649, length 16
	if (len === 16) {
		if (s.startsWith('6011')) return true;
		if (s.startsWith('65')) return true;
		if (p3 >= 644 && p3 <= 649) return true;
	}

	// JCB: 3528-3589, length 16
	if (len === 16 && p4 >= 3528 && p4 <= 3589) return true;

	// Diners Club: 300-305, 36, 38, length 14
	if (len === 14) {
		if (p3 >= 300 && p3 <= 305) return true;
		if (s.startsWith('36')) return true;
		if (s.startsWith('38')) return true;
	}

	return false;
}

function isLikelyCardDigits(digits) {
	const s = String(digits || '');
	if (!s || !/^\d+$/.test(s)) return false;
	if (s.length < 13 || s.length > 19) return false;
	// avoid obvious junk like "0000..." (Luhn may still pass for some patterns)
	let allSame = true;
	for (let i = 1; i < s.length; i++) {
		if (s[i] !== s[0]) {
			allSame = false;
			break;
		}
	}
	if (allSame) return false;
	// Luhn alone can still match unrelated numeric IDs; additionally require a known card scheme pattern.
	if (!luhnCheck(s)) return false;
	return matchesKnownCardScheme(s);
}

function extractCardNumbers(text, maxMatches) {
	const s = String(text || '');
	if (!s) return [];
	const matches = [];
	let m;
	CARD_CANDIDATE_REGEX.lastIndex = 0;
	while ((m = CARD_CANDIDATE_REGEX.exec(s))) {
		const raw = m[0];
		const digits = String(raw || '').replace(/\D+/g, '');
		if (!isLikelyCardDigits(digits)) continue;
		matches.push(digits);
		if (matches.length >= maxMatches) break;
	}
	return uniqueStringsLimit(matches, maxMatches);
}

function normalizeJapanesePhoneNumber(raw) {
	let s = String(raw || '').trim();
	if (!s) return '';
	s = s.replace(/[０-９]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) - 0xfee0));
	s = s.replace(/\(0\)/g, '');
	s = s.replace(/[^\d+]/g, '');
	if (s.startsWith('+81')) {
		s = `0${s.slice(3)}`;
	}
	if (!/^\d+$/.test(s)) return '';
	if (!s.startsWith('0')) return '';
	if (s.length < 10 || s.length > 11) return '';
	return s;
}

function isLikelyJapanesePhoneNumber(digits) {
	const s = String(digits || '');
	if (!/^0\d{9,10}$/.test(s)) return false;
	if (/^0+$/.test(s)) return false;

	// Mobile/PHS numbers: 070/080/090 + 8 digits.
	if (/^0[789]0\d{8}$/.test(s)) return true;

	// Toll-free/navigation/premium-ish service numbers commonly seen in Japan.
	if (/^0(120|800|570|990)\d{6}$/.test(s)) return true;

	// Landline/IP phone: 0 + area/provider prefix, total 10 digits.
	if (s.length === 10 && /^0[1-9]\d{8}$/.test(s)) return true;

	return false;
}

function extractPhoneNumbers(text, maxMatches) {
	const s = String(text || '');
	if (!s) return [];
	const matches = [];
	let m;
	PHONE_CANDIDATE_REGEX.lastIndex = 0;
	while ((m = PHONE_CANDIDATE_REGEX.exec(s))) {
		const digits = normalizeJapanesePhoneNumber(m[0]);
		if (!isLikelyJapanesePhoneNumber(digits)) continue;
		matches.push(digits);
		if (matches.length >= maxMatches) break;
	}
	return uniqueStringsLimit(matches, maxMatches);
}

function maskCardNumber(cardDigits) {
	const d = String(cardDigits || '').replace(/\D+/g, '');
	if (d.length < 4) return '(card)';
	const last4 = d.slice(-4);
	const masked = `${'*'.repeat(Math.max(0, d.length - 4))}${last4}`;
	const groups = [];
	for (let i = 0; i < masked.length; i += 4) {
		groups.push(masked.slice(i, i + 4));
	}
	return groups.join(' ').trim();
}

function maskPhoneNumber(phoneDigits) {
	const d = String(phoneDigits || '').replace(/\D+/g, '');
	if (d.length < 4) return '(phone)';
	const last4 = d.slice(-4);
	return `${d.slice(0, 3)}-****-${last4}`;
}

// メールアドレスをマスクする例: "user@example.com" -> "u***@example.com"
// - ダッシュボード一覧では原文を出さず、まずはマスクして“検出された事実”だけ見せる。
function maskEmail(email) {
	const s = String(email || '');
	const at = s.indexOf('@');
	if (at <= 0) return '(email)';
	const local = s.slice(0, at);
	const domain = s.slice(at + 1);
	const first = local.slice(0, 1);
	return `${first}***@${domain}`;
}

// decodeURIComponent は不正な%エスケープで例外になることがあるので、失敗したら''にする。
function safeDecodeURIComponent(input) {
	const s = String(input || '');
	if (!s) return '';
	try {
		return decodeURIComponent(s);
	} catch {
		// 不正な %xx が混ざると decodeURIComponent は例外を投げる。
		// ここで落とすとプロキシ全体のログ処理に影響するので、安全側に倒して''扱いにする。
		return '';
	}
}

function isCardRelatedParamName(name) {
	const s = String(name || '').toLowerCase();
	if (!s) return false;
	// Keep this conservative to reduce false positives in analytics/telemetry endpoints.
	// Examples to match: cc, card, card_number, payment, pan
	return /(^|[_-])(cc|card|cardnumber|card_number|pan|payment|pay|acct|account|number)([_-]|$)/i.test(s);
}

function extractCardCandidatesFromUrl(url) {
	const candidates = [];
	try {
		const u = new URL(String(url || ''));
		for (const [k, v] of u.searchParams.entries()) {
			const key = String(k || '');
			const val = String(v || '');
			if (!val) continue;
			// Heuristic: only scan query values that look card-related.
			// - either parameter name indicates payment/card
			// - or the value is formatted (spaces/hyphens) which is uncommon for random IDs
			const formatted = /[ -]/.test(val);
			if (!isCardRelatedParamName(key) && !formatted) continue;
			candidates.push(val);
			const decoded = safeDecodeURIComponent(val);
			if (decoded && decoded !== val) candidates.push(decoded);
		}
	} catch {
		// ignore
	}
	return candidates;
}

// URLやボディ、フォームフィールドなどからメールアドレスを検出してログのフィールドを生成するロジック
// - ここで返すオブジェクトは、そのままログエントリに Object.assign で混ぜられる想定。
// - request/response本文のデコードは src/httpBody.js に委譲する（ここでは文字列探索だけ）。
function buildEmailPiiFields({ url, requestBodyText, requestBodyTruncated, responseBodyText, responseBodyTruncated, formFields }) {
	const urlCandidates = [];
	urlCandidates.push(String(url || ''));
	const decodedUrl = safeDecodeURIComponent(url);
	if (decodedUrl && decodedUrl !== url) urlCandidates.push(decodedUrl);
	try {
		// URLSearchParams は %xx をデコードした値を返す（例: %40 -> @）
		const u = new URL(String(url || ''));
		for (const v of u.searchParams.values()) {
			urlCandidates.push(v);
		}
	} catch {
		// ignore
	}
	const urlMatches = extractEmails(urlCandidates.join('\n'), 20);

	const requestBodyCandidates = [];
	requestBodyCandidates.push(String(requestBodyText || ''));
	const decodedRequestBody = safeDecodeURIComponent(requestBodyText);
	if (decodedRequestBody && decodedRequestBody !== requestBodyText) requestBodyCandidates.push(decodedRequestBody);
	const requestBodyMatches = extractEmails(requestBodyCandidates.join('\n'), 20);

	const responseBodyCandidates = [];
	responseBodyCandidates.push(String(responseBodyText || ''));
	const decodedResponseBody = safeDecodeURIComponent(responseBodyText);
	if (decodedResponseBody && decodedResponseBody !== responseBodyText) responseBodyCandidates.push(decodedResponseBody);
	const responseBodyMatches = extractEmails(responseBodyCandidates.join('\n'), 20);

	let fieldMatches = [];
	try {
		if (formFields && typeof formFields === 'object') {
			const rawFields = JSON.stringify(formFields);
			const decodedFields = safeDecodeURIComponent(rawFields);
			fieldMatches = extractEmails([rawFields, decodedFields].filter(Boolean).join('\n'), 20);
		}
	} catch {
		fieldMatches = [];
	}

	const all = uniqueStringsLimit([...urlMatches, ...requestBodyMatches, ...responseBodyMatches, ...fieldMatches], 20);
	if (all.length === 0) return {};

	return {
		piiEmailDetected: true,
		piiEmailCount: all.length,
		piiEmailSamples: all.slice(0, 5).map(maskEmail),
		piiEmailInUrl: urlMatches.length > 0,
		// Backward compatible name: this refers to the *request* body.
		piiEmailInBody: requestBodyMatches.length > 0,
		piiEmailInRequestBody: requestBodyMatches.length > 0,
		piiEmailInResponse: responseBodyMatches.length > 0,
		piiEmailInFormFields: fieldMatches.length > 0,
		// Backward compatible name: this refers to the *request* body.
		piiEmailBodyTruncated: Boolean(requestBodyTruncated),
		piiEmailRequestBodyTruncated: Boolean(requestBodyTruncated),
		piiEmailResponseBodyTruncated: Boolean(responseBodyTruncated),
	};
}

function buildCardPiiFields({ url, requestBodyText, requestBodyTruncated, responseBodyText, responseBodyTruncated, formFields }) {
	// NOTE: To reduce false positives, avoid scanning the full URL (host/path often contain numeric IDs).
	// Scan only card-related query parameters or formatted values.
	const urlMatches = extractCardNumbers(extractCardCandidatesFromUrl(url).join('\n'), 20);

	const requestBodyCandidates = [];
	requestBodyCandidates.push(String(requestBodyText || ''));
	const decodedRequestBody = safeDecodeURIComponent(requestBodyText);
	if (decodedRequestBody && decodedRequestBody !== requestBodyText) requestBodyCandidates.push(decodedRequestBody);
	const requestBodyMatches = extractCardNumbers(requestBodyCandidates.join('\n'), 20);

	const responseBodyCandidates = [];
	responseBodyCandidates.push(String(responseBodyText || ''));
	const decodedResponseBody = safeDecodeURIComponent(responseBodyText);
	if (decodedResponseBody && decodedResponseBody !== responseBodyText) responseBodyCandidates.push(decodedResponseBody);
	const responseBodyMatches = extractCardNumbers(responseBodyCandidates.join('\n'), 20);

	let fieldMatches = [];
	try {
		if (formFields && typeof formFields === 'object') {
			const rawFields = JSON.stringify(formFields);
			const decodedFields = safeDecodeURIComponent(rawFields);
			fieldMatches = extractCardNumbers([rawFields, decodedFields].filter(Boolean).join('\n'), 20);
		}
	} catch {
		fieldMatches = [];
	}

	const all = uniqueStringsLimit([...urlMatches, ...requestBodyMatches, ...responseBodyMatches, ...fieldMatches], 20);
	if (all.length === 0) return {};

	return {
		piiCardDetected: true,
		piiCardCount: all.length,
		piiCardSamples: all.slice(0, 5).map(maskCardNumber),
		piiCardInUrl: urlMatches.length > 0,
		// Backward compatible name: this refers to the *request* body.
		piiCardInBody: requestBodyMatches.length > 0,
		piiCardInRequestBody: requestBodyMatches.length > 0,
		piiCardInResponse: responseBodyMatches.length > 0,
		piiCardInFormFields: fieldMatches.length > 0,
		// Backward compatible name: this refers to the *request* body.
		piiCardBodyTruncated: Boolean(requestBodyTruncated),
		piiCardRequestBodyTruncated: Boolean(requestBodyTruncated),
		piiCardResponseBodyTruncated: Boolean(responseBodyTruncated),
	};
}

function buildPhonePiiFields({ url, requestBodyText, requestBodyTruncated, responseBodyText, responseBodyTruncated, formFields }) {
	const urlCandidates = [];
	urlCandidates.push(String(url || ''));
	const decodedUrl = safeDecodeURIComponent(url);
	if (decodedUrl && decodedUrl !== url) urlCandidates.push(decodedUrl);
	try {
		const u = new URL(String(url || ''));
		for (const v of u.searchParams.values()) {
			urlCandidates.push(v);
		}
	} catch {
		// ignore
	}
	const urlMatches = extractPhoneNumbers(urlCandidates.join('\n'), 20);

	const requestBodyCandidates = [];
	requestBodyCandidates.push(String(requestBodyText || ''));
	const decodedRequestBody = safeDecodeURIComponent(requestBodyText);
	if (decodedRequestBody && decodedRequestBody !== requestBodyText) requestBodyCandidates.push(decodedRequestBody);
	const requestBodyMatches = extractPhoneNumbers(requestBodyCandidates.join('\n'), 20);

	const responseBodyCandidates = [];
	responseBodyCandidates.push(String(responseBodyText || ''));
	const decodedResponseBody = safeDecodeURIComponent(responseBodyText);
	if (decodedResponseBody && decodedResponseBody !== responseBodyText) responseBodyCandidates.push(decodedResponseBody);
	const responseBodyMatches = extractPhoneNumbers(responseBodyCandidates.join('\n'), 20);

	let fieldMatches = [];
	try {
		if (formFields && typeof formFields === 'object') {
			const rawFields = JSON.stringify(formFields);
			const decodedFields = safeDecodeURIComponent(rawFields);
			fieldMatches = extractPhoneNumbers([rawFields, decodedFields].filter(Boolean).join('\n'), 20);
		}
	} catch {
		fieldMatches = [];
	}

	const all = uniqueStringsLimit([...urlMatches, ...requestBodyMatches, ...responseBodyMatches, ...fieldMatches], 20);
	if (all.length === 0) return {};

	return {
		piiPhoneDetected: true,
		piiPhoneCount: all.length,
		piiPhoneSamples: all.slice(0, 5).map(maskPhoneNumber),
		piiPhoneInUrl: urlMatches.length > 0,
		// Backward compatible shape: "InBody" refers to request body.
		piiPhoneInBody: requestBodyMatches.length > 0,
		piiPhoneInRequestBody: requestBodyMatches.length > 0,
		piiPhoneInResponse: responseBodyMatches.length > 0,
		piiPhoneInFormFields: fieldMatches.length > 0,
		piiPhoneBodyTruncated: Boolean(requestBodyTruncated),
		piiPhoneRequestBodyTruncated: Boolean(requestBodyTruncated),
		piiPhoneResponseBodyTruncated: Boolean(responseBodyTruncated),
	};
}

// ログエントリ（JSONLの1行）から、後からカード番号候補（digit列）を再抽出する。
// - ダッシュボード表示補完のため。ここでは raw の digit 列を返す（表示側で mask する前提）。
function computeCardMatchesFromLogEntry(entry) {
	if (!entry) return [];
	const parts = [];
	try {
		if (entry.URL) {
			parts.push(extractCardCandidatesFromUrl(String(entry.URL)).join('\n'));
		}
	} catch {
		// ignore
	}

	function tryAddBody(prefix) {
		try {
			const textKey = `${prefix}BodyText`;
			const base64Key = `${prefix}BodyBase64`;
			const ctKey = `${prefix}ContentType`;
			const encKey = `${prefix}ContentEncoding`;
			const text = entry[textKey];
			if (typeof text === 'string' && text) {
				parts.push(text);
				return;
			}
			const base64 = entry[base64Key];
			if (typeof base64 === 'string' && base64) {
				const buf = Buffer.from(base64, 'base64');
				const decoded = decodeTextBodyForPii(buf, entry[ctKey] || '', entry[encKey] || '');
				if (decoded) parts.push(decoded);
			}
		} catch {
			// ignore
		}
	}

	tryAddBody('request');
	tryAddBody('response');

	try {
		if (entry.requestFormFields && typeof entry.requestFormFields === 'object') {
			parts.push(JSON.stringify(entry.requestFormFields));
		}
	} catch {
		// ignore
	}

	return extractCardNumbers(parts.join('\n'), 50);
}

function computePhoneMatchesFromLogEntry(entry) {
	if (!entry) return [];
	const parts = [];
	try {
		if (entry.URL) parts.push(String(entry.URL));
	} catch {
		// ignore
	}

	function tryAddBody(prefix) {
		try {
			const textKey = `${prefix}BodyText`;
			const base64Key = `${prefix}BodyBase64`;
			const ctKey = `${prefix}ContentType`;
			const encKey = `${prefix}ContentEncoding`;
			const text = entry[textKey];
			if (typeof text === 'string' && text) {
				parts.push(text);
				return;
			}
			const base64 = entry[base64Key];
			if (typeof base64 === 'string' && base64) {
				const buf = Buffer.from(base64, 'base64');
				const decoded = decodeTextBodyForPii(buf, entry[ctKey] || '', entry[encKey] || '');
				if (decoded) parts.push(decoded);
			}
		} catch {
			// ignore
		}
	}

	tryAddBody('request');
	tryAddBody('response');

	try {
		if (entry.requestFormFields && typeof entry.requestFormFields === 'object') {
			parts.push(JSON.stringify(entry.requestFormFields));
		}
	} catch {
		// ignore
	}

	return extractPhoneNumbers(parts.join('\n'), 50);
}

// ログエントリ（JSONLの1行）から、後からメール候補を再抽出する。
// - ダッシュボードで「詳細ページを開いた時」などに、保存済みフィールドから再スキャンできる。
// - request/response本文は text が無ければ base64 を復元→decodeTextBodyForPii で文字列化を試みる。
function computeEmailMatchesFromLogEntry(entry) {
	if (!entry) return [];
	const parts = [];
	try {
		if (entry.URL) parts.push(String(entry.URL));
	} catch {
		// ignore
	}

	function tryAddBody(prefix) {
		try {
			const textKey = `${prefix}BodyText`;
			const base64Key = `${prefix}BodyBase64`;
			const ctKey = `${prefix}ContentType`;
			const encKey = `${prefix}ContentEncoding`;
			const text = entry[textKey];
			if (typeof text === 'string' && text) {
				parts.push(text);
				return;
			}
			const base64 = entry[base64Key];
			if (typeof base64 === 'string' && base64) {
				// base64をいったんバイト列に戻し、Content-Type/Encoding を頼りにテキスト化を試みる。
				// - 画像などは decodeTextBodyForPii が '' を返す想定。
				const buf = Buffer.from(base64, 'base64');
				const decoded = decodeTextBodyForPii(buf, entry[ctKey] || '', entry[encKey] || '');
				if (decoded) parts.push(decoded);
			}
		} catch {
			// ignore
		}
	}

	tryAddBody('request');
	tryAddBody('response');

	try {
		if (entry.requestFormFields && typeof entry.requestFormFields === 'object') {
			parts.push(JSON.stringify(entry.requestFormFields));
		}
	} catch {
		// ignore
	}

	return extractEmails(parts.join('\n'), 50);
}

module.exports = {
	buildEmailPiiFields,
	buildCardPiiFields,
	buildPhonePiiFields,
	computeEmailMatchesFromLogEntry,
	computeCardMatchesFromLogEntry,
	computePhoneMatchesFromLogEntry,
	extractEmails,
	extractCardNumbers,
	extractPhoneNumbers,
	maskEmail,
	maskCardNumber,
	maskPhoneNumber,
};
