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
	computeEmailMatchesFromLogEntry,
	extractEmails,
	maskEmail,
};
