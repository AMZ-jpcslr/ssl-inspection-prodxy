/*
メモ
ダッシュボード HTML 生成（純粋関数寄り）

このファイルの担当
- ログエントリ一覧/詳細（body/PII）の HTML を文字列として生成する
- XSS を避けるため、ユーザー由来テキストを escape する
- ダッシュボードで扱える量に制限しつつ、ログ（JSONL）の情報を“要約”表示する
- 一覧→詳細リンクの参照ズレを防ぐため、エントリから安定キー（hash由来）を作る

要点
- UIはテンプレートエンジンを使わず、サーバ側でHTML文字列を組み立て（依存を増やさないMVP）。
- 文字列は必ずHTMLエスケープして挿入します。
- `piiEmailSamples` が空の場合でも、ログに保存した URL/本文/フォーム情報から
	`computeEmailMatchesFromLogEntry` で“オンデマンド再スキャン”して表示を補完します。
*/

const crypto = require('node:crypto');

// pii.js からマスク/検出ロジックをインポート
const { maskEmail, computeEmailMatchesFromLogEntry, maskCardNumber, computeCardMatchesFromLogEntry } = require('../pii');

// ダッシュボードで表示するログエントリの本文やURLなどを切り詰める上限値
// 前者がフォームフィールド用、後者がURLや本文用の上限値（両方ともMVPの割り切りで設定）。
// 単位は文字数（厳密にはUTF-16コードユニット数）。この上限を超えると、ダッシュボードでは切り詰めて表示し、JSONLには全量保存する。
const DASHBOARD_MAX_FORMFIELDS_CHARS = 2000;
const DASHBOARD_BODY_PAGE_MAX_CHARS = 200_000;

// HTMLエスケープとダッシュボード用のテキスト処理ロジック
// 例:<script>のような文字列がタグとして解釈されるのを防ぐ
// - ユーザー由来文字列（URL/本文/ファイル名など）をHTMLに埋め込むときは必ずエスケープする。
// どこに効く？
// - これは「HTMLのテキスト部分」や「HTML属性値」に入れるときの安全化。
// - URLのクエリパラメータを作るときは `encodeURIComponent()` を使う（目的が違う）。
//   例: `/entry/${encodeURIComponent(id)}/body?prefix=request`
function escapeHtml(s) {
	return String(s)
		.replaceAll('&', '&amp;')
		.replaceAll('<', '&lt;')
		.replaceAll('>', '&gt;')
		.replaceAll('"', '&quot;')
		.replaceAll("'", '&#39;');
}

// 長い文字列をダッシュボード表示用に切り詰める。
// - ログ(JSONL)は全量を保存しうるが、UIで全表示すると重いので上限を設ける。
function truncateForDashboard(s, maxChars) {
	const limit = Number.isFinite(maxChars) ? Math.max(0, maxChars) : 0;
	const text = String(s || '');
	if (limit === 0) return '';
	if (text.length <= limit) return text;
	return `${text.slice(0, limit)}\n…(truncated in dashboard; full content is in JSONL)`;
}

// request/response body の「表のセル1個ぶん」のHTMLを作る。
// - そのまま本文を埋め込まず、「view」リンクで別ページ表示に分離する。
// - 画像等がファイル保存されている場合は download リンクを表示する。
function renderBodyCell(entry, prefix, dashId) {
	// prefix は 'request' / 'response' のどちらか。
	// - ログ(JSONL)のフィールド名は requestBodyText / responseBodyText のように prefix で分かれているので、
	//   `${prefix}BodyText` の形で同じロジックを共通化している。
	// - ここでは「一覧の1セル」に収まるよう、本文の中身ではなく“要約＋リンク”を返す。
	const bytes = entry && typeof entry[`${prefix}BodyBytes`] === 'number' ? entry[`${prefix}BodyBytes`] : 0;
	const truncated = Boolean(entry && entry[`${prefix}BodyTruncated`]);
	const contentType = escapeHtml((entry && entry[`${prefix}ContentType`]) || '');
	const contentEncoding = escapeHtml((entry && entry[`${prefix}ContentEncoding`]) || '');
	const charset = escapeHtml((entry && entry[`${prefix}Charset`]) || '');

	// 分岐1: 「ファイルとして保存したかったがスキップした」ケース
	// - 例: 大きすぎる、書き込みエラー、など。
	const fileSkipped = Boolean(entry && entry[`${prefix}BodyFileSkipped`]);
	if (fileSkipped) {
		const reason = escapeHtml((entry && entry[`${prefix}BodyFileSkipReason`]) || 'skipped');
		const maxBytes =
			entry && typeof entry[`${prefix}BodyFileMaxBytes`] === 'number'
				? ` max=${entry[`${prefix}BodyFileMaxBytes`]}B`
				: '';
		return `<span style="color:#444">(file skipped: ${reason}${maxBytes})</span>`;
	}

	// 分岐2: 本文がファイルとして保存されているケース
	// - 画像レスポンスやアップロード画像などは、ログにbase64で埋め込むよりファイル保存の方が現実的。
	const fileUrl = entry && typeof entry[`${prefix}BodyFileUrl`] === 'string' ? entry[`${prefix}BodyFileUrl`] : '';
	if (fileUrl) {
		const fileBytes = entry && typeof entry[`${prefix}BodyFileBytes`] === 'number' ? entry[`${prefix}BodyFileBytes`] : bytes;
		const summary = `${fileBytes}B${truncated ? '…' : ''} file`;
		const meta = [contentType, charset ? `charset=${charset}` : '', contentEncoding ? `enc=${contentEncoding}` : '']
			.filter(Boolean)
			.join(' ');
		// rel="noopener noreferrer" は target="_blank" のときの安全策（別タブからwindow.opener経由で干渉されるのを避ける）。
		return `<div>
			<div><a href="${escapeHtml(fileUrl)}" target="_blank" rel="noopener noreferrer">download</a></div>
			<div style="color:#444">${escapeHtml(summary)}${meta ? ` (${escapeHtml(meta)})` : ''}</div>
		</div>`;
	}

    // 分岐3: 本文が直接ログに埋め込まれているケース
    // - 例: 小さめのテキストレスポンスやリクエストボディなど。
	const text = entry && typeof entry[`${prefix}BodyText`] === 'string' ? entry[`${prefix}BodyText`] : '';

    // どちらのケースでもない（本文なし）の場合は、(none) 表示にする。
	const base64 = entry && typeof entry[`${prefix}BodyBase64`] === 'string' ? entry[`${prefix}BodyBase64`] : '';
	if (!text && !base64) {
		return `<span style="color:#444">(none)</span>`;
	}

    // 本文がある場合は、ダッシュボードで表示するための要約とリンクを返す。
	const kind = text ? 'text' : 'base64';
	const summary = `${bytes}B${truncated ? '…' : ''} ${kind}`;
	const meta = [contentType, charset ? `charset=${charset}` : '', contentEncoding ? `enc=${contentEncoding}` : '']
		.filter(Boolean)
		.join(' ');
	// dashId はURLパスの一部になるので encodeURIComponent でURLとして安全な文字列にする。
	// - HTMLに埋め込む段階では escapeHtml も必要になるが、ここはまずURLを正しく作る。
	const idPart = dashId === undefined || dashId === null || dashId === '' ? '' : encodeURIComponent(String(dashId));
	const viewUrl = idPart ? `/entry/${idPart}/body?prefix=${prefix}` : '';
	return `<div>
		<div>${viewUrl ? `<a href="${viewUrl}" target="_blank" rel="noopener noreferrer">view</a>` : ''}</div>
		<div style="color:#444">${escapeHtml(summary)}${meta ? ` (${escapeHtml(meta)})` : ''}</div>
	</div>`;
}

// multipart でアップロードされたファイル一覧（リンク）を表示する。
// - src/main.js が保存したファイルを /files/... で配信し、そのURLをログに残している。
function renderUploadedFiles(entry) {
	if (!entry || !Array.isArray(entry.requestUploadedFiles) || entry.requestUploadedFiles.length === 0) {
		return '';
	}
	const items = entry.requestUploadedFiles
		.map((f) => {
			const url = f && typeof f.url === 'string' ? f.url : '';
			const mime = f && typeof f.mimeType === 'string' ? f.mimeType : '';
			const bytes = f && typeof f.bytes === 'number' ? f.bytes : 0;
			const name = f && typeof f.originalFilename === 'string' && f.originalFilename ? f.originalFilename : '(file)';
			if (!url) return '';
			return `<li><a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(
				name
			)}</a> <span style="color:#444">(${escapeHtml(mime)} ${bytes}B)</span></li>`;
		})
		.filter(Boolean)
		.join('');
	if (!items) return '';
	return `<div style="margin-bottom:6px"><div style="color:#444">uploaded files:</div><ul style="margin:4px 0 0 18px">${items}</ul></div>`;
}

// multipart の補足情報（フォームフィールド/スキップしたファイル/エラー）を details で表示する。
function renderMultipartMeta(entry) {
	if (!entry || entry.requestMultipart !== true) return '';

	let fieldsHtml = '';
	try {
		const fields = entry.requestFormFields && typeof entry.requestFormFields === 'object' ? entry.requestFormFields : null;
		const keys = fields ? Object.keys(fields) : [];
		if (keys.length > 0) {
			const fieldsJson = JSON.stringify(fields, null, 2);
			const fieldsPreview = truncateForDashboard(fieldsJson, DASHBOARD_MAX_FORMFIELDS_CHARS);
			fieldsHtml = `<details>
				<summary>form fields (${keys.length})</summary>
				<pre style="white-space:pre-wrap; word-break:break-word; margin:8px 0 0 0; max-height:200px; overflow:auto;">${escapeHtml(
					fieldsPreview
				)}</pre>
			</details>`;
		}
	} catch {
		// ignore
	}

	let skippedHtml = '';
	if (Array.isArray(entry.requestUploadedFilesSkipped) && entry.requestUploadedFilesSkipped.length > 0) {
		skippedHtml = `<div style="color:#444">skipped files: ${entry.requestUploadedFilesSkipped.length}</div>`;
	}

	let errorsHtml = '';
	if (Array.isArray(entry.requestMultipartErrors) && entry.requestMultipartErrors.length > 0) {
		errorsHtml = `<div style="color:#a00">multipart errors: ${escapeHtml(entry.requestMultipartErrors.join('; '))}</div>`;
	}

	return `${skippedHtml}${errorsHtml}${fieldsHtml}`;
}

// PII検出の警告表示（一覧用）。
// - 検出箇所（url/body/response/form）を簡易表示する。
function renderPiiWarnings(entry, dashId) {
	if (!entry) return '';
	const idPart = dashId === undefined || dashId === null || dashId === '' ? '' : encodeURIComponent(String(dashId));
	const viewLink = idPart ? ` <a href="/entry/${idPart}/pii" target="_blank" rel="noopener noreferrer">view</a>` : '';

	const out = [];
	if (entry.piiEmailDetected === true) {
		const count = typeof entry.piiEmailCount === 'number' ? entry.piiEmailCount : 1;
		const where = [
			entry.piiEmailInUrl ? 'url' : '',
			entry.piiEmailInBody ? 'body' : '',
			entry.piiEmailInResponse ? 'response' : '',
			entry.piiEmailInFormFields ? 'form' : '',
		]
			.filter(Boolean)
			.join(',');
		const extra = where ? ` <span style="color:#444">(${escapeHtml(where)})</span>` : '';
		out.push(`<div style="color:#a00; font-weight:600">PII(email) detected (${count})${extra}${viewLink}</div>`);
	}

	if (entry.piiCardDetected === true) {
		const count = typeof entry.piiCardCount === 'number' ? entry.piiCardCount : 1;
		const where = [
			entry.piiCardInUrl ? 'url' : '',
			entry.piiCardInBody ? 'body' : '',
			entry.piiCardInResponse ? 'response' : '',
			entry.piiCardInFormFields ? 'form' : '',
		]
			.filter(Boolean)
			.join(',');
		const extra = where ? ` <span style="color:#444">(${escapeHtml(where)})</span>` : '';

		let maskedSamples = Array.isArray(entry.piiCardSamples) ? entry.piiCardSamples : [];
		if (maskedSamples.length === 0) {
			try {
				maskedSamples = computeCardMatchesFromLogEntry(entry).slice(0, 5).map(maskCardNumber);
			} catch {
				maskedSamples = [];
			}
		}
		const sampleText = maskedSamples.length ? ` <span style="color:#444">${escapeHtml(maskedSamples.join(', '))}</span>` : '';
		out.push(`<div style="color:#a00; font-weight:600">PII(card) detected (${count})${extra}${sampleText}</div>`);
	}

	return out.join('');
}

function computeDashboardEntryKey(entry) {
	// Stable-ish key to avoid index drift when new logs arrive.
	// - index指定だけだとログが増えたとき参照がズレるので、エントリ内容から短いhashを作る。
	try {
		const payload = JSON.stringify([
			entry && entry.timestamp ? String(entry.timestamp) : '',
			entry && entry.domain ? String(entry.domain) : '',
			entry && entry.URL ? String(entry.URL) : '',
			entry && entry.method ? String(entry.method) : '',
			entry && entry.status !== undefined && entry.status !== null ? String(entry.status) : '',
		]);
		return crypto.createHash('sha256').update(payload).digest('hex').slice(0, 16);
	} catch {
		return '';
	}
}

// ダッシュボードのメイン一覧HTMLを生成する。
// - entries は server.js で読み込んだログエントリ配列（最新が先頭になるよう整形済み）。
// - opts には authEnabled / blockDomains / message などを渡す。
function renderDashboardHtml(entries, opts) {
	const options = opts && typeof opts === 'object' ? opts : {};
	const authEnabled = options.authEnabled === true;
	const message = typeof options.message === 'string' ? options.message : '';
	const blockDomains = Array.isArray(options.blockDomains) ? options.blockDomains : [];
	const csrfToken = typeof options.csrfToken === 'string' ? options.csrfToken : '';
	const healthStatus = Array.isArray(options.healthStatus) ? options.healthStatus : [];
	const blocklistText = blockDomains.join('\n');
	const messageHtml = message
		? `<div class="meta" style="color:#060">${escapeHtml(message)}</div>`
		: '';

	const csrfInput = csrfToken ? `<input type="hidden" name="csrfToken" value="${escapeHtml(csrfToken)}" />` : '';
	const healthHtml = healthStatus.length
		? `<div class="card">
		<div style="font-weight:600; margin-bottom:8px;">Health</div>
		<div class="health-grid">
			${healthStatus
				.map((item) => {
					const ok = item && item.ok === true;
					const label = escapeHtml((item && item.label) || '');
					const detail = escapeHtml((item && item.detail) || '');
					return `<div class="health-item ${ok ? 'ok' : 'warn'}">
						<div style="font-weight:600">${ok ? 'OK' : 'CHECK'} ${label}</div>
						<div style="color:#444; word-break:break-word">${detail}</div>
					</div>`;
				})
				.join('')}
		</div>
	</div>`
		: '';

	const adminPanelHtml = `<div class="card">
		<div style="display:flex; gap:12px; align-items:center; justify-content:space-between; flex-wrap:wrap;">
			<div style="font-weight:600">Admin</div>
			<div style="display:flex; gap:12px; align-items:center;">
				<a href="/audit">audit log</a>
				${authEnabled ? `<a href="/logout">logout</a>` : ''}
			</div>
		</div>
		<div style="margin-top:10px; color:#444;">Blocked domains (one per line). Saved changes apply immediately to the proxy.</div>
		<form method="post" action="/settings/blocking" style="margin-top:10px;">
			${csrfInput}
			<textarea name="blockDomains" rows="6" style="width:100%; box-sizing:border-box;">${escapeHtml(
				blocklistText
			)}</textarea>
			<div style="margin-top:10px; display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
				<button type="submit">save</button>
				<span style="color:#444">Current count: ${escapeHtml(String(blockDomains.length))}</span>
			</div>
		</form>
		<form method="post" action="/settings/logs/clear" style="margin-top:10px;" onsubmit="return confirm('Clear access log?');">
			${csrfInput}
			<button type="submit">clear access log</button>
			<span style="color:#444; margin-left:8px;">Use before demos or after capturing sensitive traffic.</span>
		</form>
	</div>`;

	const rows = entries
		.map((e) => {
			const dashId = e && typeof e._dashKey === 'string' && e._dashKey ? e._dashKey : e && Number.isFinite(e._dashId) ? e._dashId : undefined;
			const ts = escapeHtml(e.timestamp || '');
			const domain = escapeHtml(e.domain || '');
			const url = escapeHtml(e.URL || '');
			const method = escapeHtml(e.method || '');
			const status = escapeHtml(String(e.status === undefined || e.status === null ? '' : e.status));
			const piiWarnings = renderPiiWarnings(e, dashId);
			const piiRowClass = e && (e.piiEmailDetected === true || e.piiCardDetected === true) ? ' class="pii-row"' : '';
			const uploadedFiles = renderUploadedFiles(e);
			const multipartMeta = renderMultipartMeta(e);
			const reqBodyCell = `${uploadedFiles}${multipartMeta}${renderBodyCell(e, 'request', dashId)}`;
			const resBodyCell = renderBodyCell(e, 'response', dashId);
			return `<tr${piiRowClass}>
				<td>${ts}</td>
				<td>${domain}</td>
				<td>${method}</td>
				<td>${status}</td>
				<td style="word-break:break-all">${piiWarnings}<div>${url}</div></td>
				<td>${reqBodyCell}</td>
				<td>${resBodyCell}</td>
			</tr>`;
		})
		.join('');

	return `<!doctype html>
<html lang="ja">
	<head>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<title>Proxy Logs</title>
		<style>
			body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 16px; }
			.card { border: 1px solid #ddd; border-radius: 8px; padding: 12px; margin: 0 0 12px 0; }
			.health-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px; }
			.health-item { border: 1px solid #ddd; border-radius: 6px; padding: 8px; }
			.health-item.ok { border-left: 4px solid #087f23; }
			.health-item.warn { border-left: 4px solid #b26a00; }
			textarea { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
			table { width: 100%; border-collapse: collapse; }
			th, td { border-bottom: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
			th { position: sticky; top: 0; background: #fff; }
			.meta { margin: 0 0 12px 0; color: #444; }
			.pii-row td:first-child { border-left: 4px solid #a00; }
			/* Make the summary columns stand out (timestamp..URL), but keep body columns readable */
			.pii-row td:nth-child(-n+5) { color: #a00; font-weight: 600; }
		</style>
	</head>
	<body>
		${healthHtml}
		${adminPanelHtml}
		${messageHtml}
		<p class="meta">最新 ${entries.length} 件（更新はリロード）</p>
		<table>
			<thead>
				<tr>
					<th>timestamp</th>
					<th>domain</th>
					<th>method</th>
					<th>status</th>
					<th>URL</th>
					<th>request body</th>
					<th>response body</th>
				</tr>
			</thead>
			<tbody>
				${rows}
			</tbody>
		</table>
	</body>
</html>`;
}

// PII詳細ページ（/entry/:id/pii）のHTMLを生成する。
// - wantReveal=1 のとき、生の一致候補（raw）も表示する（ただし authEnabled のときだけ）。
// - 生データはログ保存済みフィールドから再計算する（過去ログもオンデマンド再スキャンできる）。
function renderPiiDetailHtml({ entry, idParam, index, authEnabled, wantReveal }) {
	const detected = entry && entry.piiEmailDetected === true;
	const count = typeof entry.piiEmailCount === 'number' ? entry.piiEmailCount : detected ? 1 : 0;
	const where = [
		entry.piiEmailInUrl ? 'url' : '',
		entry.piiEmailInBody ? 'request-body' : '',
		entry.piiEmailInResponse ? 'response' : '',
		entry.piiEmailInFormFields ? 'form' : '',
	]
		.filter(Boolean)
		.join(',');

	let maskedSamples = Array.isArray(entry.piiEmailSamples) ? entry.piiEmailSamples : [];
	if (detected && maskedSamples.length === 0) {
		try {
			maskedSamples = computeEmailMatchesFromLogEntry(entry).slice(0, 5).map(maskEmail);
		} catch {
			maskedSamples = [];
		}
	}

	const canReveal = authEnabled === true;
	const revealBlockedNote = wantReveal && !canReveal ? 'Raw reveal is disabled when dashboardAuth is off.' : '';

	let rawMatches = [];
	if (detected && wantReveal && canReveal) {
		rawMatches = computeEmailMatchesFromLogEntry(entry);
	}

	const maskedHtml = maskedSamples.length
		? `<pre style="white-space:pre-wrap; word-break:break-word;">${escapeHtml(JSON.stringify(maskedSamples, null, 2))}</pre>`
		: `<div style="color:#444">(no masked samples)</div>`;

	const rawHtml = rawMatches.length
		? `<pre style="white-space:pre-wrap; word-break:break-word;">${escapeHtml(JSON.stringify(rawMatches, null, 2))}</pre>`
		: wantReveal && canReveal
			? `<div style="color:#444">(no matches found from stored fields; body may be truncated or encoded)</div>`
			: '';

	const idForUrl = encodeURIComponent(String(idParam || index));
	const revealLink = detected
		? canReveal
			? `<a href="/entry/${idForUrl}/pii?reveal=1" rel="noopener noreferrer">reveal raw matches</a>`
			: `<span style="color:#444">(enable dashboardAuth to allow raw reveal)</span>`
		: '';

	return `<!doctype html>
<html lang="ja">
	<head>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<title>PII view</title>
		<style>
			body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 16px; }
			.card { border: 1px solid #ddd; border-radius: 8px; padding: 12px; }
			.meta { color: #444; margin: 0 0 10px 0; }
			h2 { margin: 14px 0 8px 0; font-size: 16px; }
		</style>
	</head>
	<body>
		<div class="meta"><a href="/">&larr; back</a></div>
		<div class="card">
			<div class="meta">domain: ${escapeHtml(String(entry.domain || ''))}</div>
			<div class="meta">url: <span style="word-break:break-all">${escapeHtml(String(entry.URL || ''))}</span></div>
			<div class="meta">PII(email): ${detected ? 'detected' : 'not detected'}${detected ? ` (count=${count}${where ? `, where=${escapeHtml(where)}` : ''})` : ''}</div>
			${revealBlockedNote ? `<div class="meta" style="color:#a00">${escapeHtml(revealBlockedNote)}</div>` : ''}
			${detected ? `<div class="meta">${revealLink}</div>` : ''}

			<h2>masked samples</h2>
			${maskedHtml}

			${wantReveal && canReveal ? `<h2>raw matches (from stored fields)</h2>${rawHtml}` : ''}
		</div>
	</body>
</html>`;
}

module.exports = {
	DASHBOARD_BODY_PAGE_MAX_CHARS,
	DASHBOARD_MAX_FORMFIELDS_CHARS,
	escapeHtml,
	truncateForDashboard,
	renderDashboardHtml,
	renderPiiDetailHtml,
	computeDashboardEntryKey,
};
