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
const {
	maskEmail,
	computeEmailMatchesFromLogEntry,
	maskCardNumber,
	computeCardMatchesFromLogEntry,
	maskPhoneNumber,
	computePhoneMatchesFromLogEntry,
} = require('../pii');

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
		const reason = escapeHtml((entry && entry[`${prefix}BodyFileSkipReason`]) || 'スキップ');
		const maxBytes =
			entry && typeof entry[`${prefix}BodyFileMaxBytes`] === 'number'
				? ` max=${entry[`${prefix}BodyFileMaxBytes`]}B`
				: '';
		return `<span style="color:#444">(ファイル保存なし: ${reason}${maxBytes})</span>`;
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
			<div><a href="${escapeHtml(fileUrl)}" target="_blank" rel="noopener noreferrer">ダウンロード</a></div>
			<div style="color:#444">${escapeHtml(summary)}${meta ? ` (${escapeHtml(meta)})` : ''}</div>
		</div>`;
	}

    // 分岐3: 本文が直接ログに埋め込まれているケース
    // - 例: 小さめのテキストレスポンスやリクエストボディなど。
	const text = entry && typeof entry[`${prefix}BodyText`] === 'string' ? entry[`${prefix}BodyText`] : '';

    // どちらのケースでもない（本文なし）の場合は、(none) 表示にする。
	const base64 = entry && typeof entry[`${prefix}BodyBase64`] === 'string' ? entry[`${prefix}BodyBase64`] : '';
	if (!text && !base64) {
		return `<span style="color:#444">(なし)</span>`;
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
		<div>${viewUrl ? `<a href="${viewUrl}" target="_blank" rel="noopener noreferrer">表示</a>` : ''}</div>
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
	return `<div style="margin-bottom:6px"><div style="color:#444">アップロードファイル:</div><ul style="margin:4px 0 0 18px">${items}</ul></div>`;
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
				<summary>フォーム項目 (${keys.length})</summary>
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
		skippedHtml = `<div style="color:#444">保存しなかったファイル: ${entry.requestUploadedFilesSkipped.length}</div>`;
	}

	let errorsHtml = '';
	if (Array.isArray(entry.requestMultipartErrors) && entry.requestMultipartErrors.length > 0) {
		errorsHtml = `<div style="color:#a00">multipart エラー: ${escapeHtml(entry.requestMultipartErrors.join('; '))}</div>`;
	}

	return `${skippedHtml}${errorsHtml}${fieldsHtml}`;
}

// PII検出の警告表示（一覧用）。
// - 検出箇所（url/body/response/form）を簡易表示する。
function renderPiiWarnings(entry, dashId) {
	if (!entry) return '';
	const idPart = dashId === undefined || dashId === null || dashId === '' ? '' : encodeURIComponent(String(dashId));
	const viewLink = idPart ? ` <a href="/entry/${idPart}/pii" target="_blank" rel="noopener noreferrer">詳細</a>` : '';

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
		out.push(`<div style="color:#a00; font-weight:600">PII(メール) 検出 (${count})${extra}${viewLink}</div>`);
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
		out.push(`<div style="color:#a00; font-weight:600">PII(カード) 検出 (${count})${extra}${sampleText}</div>`);
	}

	if (entry.piiPhoneDetected === true) {
		const count = typeof entry.piiPhoneCount === 'number' ? entry.piiPhoneCount : 1;
		const where = [
			entry.piiPhoneInUrl ? 'url' : '',
			entry.piiPhoneInBody ? 'body' : '',
			entry.piiPhoneInResponse ? 'response' : '',
			entry.piiPhoneInFormFields ? 'form' : '',
		]
			.filter(Boolean)
			.join(',');
		const extra = where ? ` <span style="color:#444">(${escapeHtml(where)})</span>` : '';

		let maskedSamples = Array.isArray(entry.piiPhoneSamples) ? entry.piiPhoneSamples : [];
		if (maskedSamples.length === 0) {
			try {
				maskedSamples = computePhoneMatchesFromLogEntry(entry).slice(0, 5).map(maskPhoneNumber);
			} catch {
				maskedSamples = [];
			}
		}
		const sampleText = maskedSamples.length ? ` <span style="color:#444">${escapeHtml(maskedSamples.join(', '))}</span>` : '';
		out.push(`<div style="color:#a00; font-weight:600">PII(電話) 検出 (${count})${extra}${sampleText}</div>`);
	}

	return out.join('');
}

function entryHasPii(entry) {
	return Boolean(entry && (entry.piiEmailDetected === true || entry.piiCardDetected === true || entry.piiPhoneDetected === true));
}

function entryHasSavedFile(entry) {
	return Boolean(
		entry &&
			((typeof entry.requestBodyFileUrl === 'string' && entry.requestBodyFileUrl) ||
				(typeof entry.responseBodyFileUrl === 'string' && entry.responseBodyFileUrl) ||
				(Array.isArray(entry.requestUploadedFiles) && entry.requestUploadedFiles.length > 0))
	);
}

function renderStatusBadges(entry) {
	if (!entry) return '';
	const badges = [];
	if (entry.isSSL === true) badges.push(['neutral', 'HTTPS']);
	if (entry.blocked === true) badges.push(['danger', 'ブロック']);
	if (entry.phishingWarning === true) badges.push(['warn', 'フィッシング警告']);
	if (entryHasPii(entry)) badges.push(['danger', 'PII']);
	if (entryHasSavedFile(entry)) badges.push(['neutral', 'ファイル']);
	if (badges.length === 0) return '';
	return `<div class="badges">${badges
		.map(([kind, label]) => `<span class="badge ${kind}">${escapeHtml(label)}</span>`)
		.join('')}</div>`;
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

function hasActiveLogFilters(filters) {
	const f = filters && typeof filters === 'object' ? filters : {};
	return Boolean(f.q || f.domain || f.method || f.status || f.onlyPii || f.onlyPhishing || f.onlyBlocked || f.onlyFiles);
}

function renderInlineList(items, emptyText) {
	const values = Array.isArray(items) ? items.filter(Boolean) : [];
	if (values.length === 0) return escapeHtml(emptyText || '(none)');
	return values.map((item) => `<code>${escapeHtml(item)}</code>`).join(', ');
}

function countDashboardEntries(entries, predicate) {
	const rows = Array.isArray(entries) ? entries : [];
	return rows.reduce((count, entry) => (predicate(entry) ? count + 1 : count), 0);
}

// ダッシュボードのメイン一覧HTMLを生成する。
// - entries は server.js で読み込んだログエントリ配列（最新が先頭になるよう整形済み）。
// - opts には authEnabled / blockDomains / message などを渡す。
function renderDashboardHtml(entries, opts) {
	const options = opts && typeof opts === 'object' ? opts : {};
	const authEnabled = options.authEnabled === true;
	const message = typeof options.message === 'string' ? options.message : '';
	const blockDomains = Array.isArray(options.blockDomains) ? options.blockDomains : [];
	const filters = options.filters && typeof options.filters === 'object' ? options.filters : {};
	const totalEntries = Number.isFinite(options.totalEntries) ? options.totalEntries : entries.length;
	const hasFilters = hasActiveLogFilters(filters);
	const csrfToken = typeof options.csrfToken === 'string' ? options.csrfToken : '';
	const healthStatus = Array.isArray(options.healthStatus) ? options.healthStatus : [];
	const logScope = options.logScope && typeof options.logScope === 'object' ? options.logScope : {};
	const caInfo = options.caInfo && typeof options.caInfo === 'object' ? options.caInfo : {};
	const configSettings = options.configSettings && typeof options.configSettings === 'object' ? options.configSettings : {};
	const autoRefreshEnabled = options.autoRefreshEnabled !== false;
	const refreshLabel = autoRefreshEnabled ? '自動更新中' : '自動更新停止中';
	const refreshToggleHref = autoRefreshEnabled ? '/?refresh=0' : '/';
	const blocklistText = blockDomains.join('\n');
	const messageHtml = message
		? `<div class="meta" style="color:#060">${escapeHtml(message)}</div>`
		: '';

	const csrfInput = csrfToken ? `<input type="hidden" name="csrfToken" value="${escapeHtml(csrfToken)}" />` : '';
	const healthHtml = healthStatus.length
		? `<div class="card">
		<div style="font-weight:600; margin-bottom:8px;">ヘルスチェック</div>
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

	const logMode = typeof logScope.mode === 'string' && logScope.mode ? logScope.mode : 'all';
	const logDomains = Array.isArray(logScope.domains) ? logScope.domains : [];
	const bodyDomains = Array.isArray(logScope.bodyDomains) ? logScope.bodyDomains : [];
	const fileDomains = Array.isArray(logScope.fileDomains) ? logScope.fileDomains : [];
	const tlsBypassDomains = Array.isArray(logScope.tlsBypassDomains) ? logScope.tlsBypassDomains : [];
	const loggingSummary =
		logMode === 'allowlist'
			? `ログ対象: ${renderInlineList(logDomains, '未設定')}`
			: 'ログ対象: すべてのドメイン';
	const bodySummary = `本文取得対象: ${renderInlineList(bodyDomains, 'すべてのドメイン')}`;
	const fileSummary = `ファイル保存対象: ${renderInlineList(fileDomains, 'すべてのドメイン')}`;
	const tlsBypassSummary = `TLSバイパス対象: ${logScope.tlsBypassEnabled === false ? '無効' : renderInlineList(tlsBypassDomains, '未設定')}`;
	const caExists = caInfo.exists === true;
	const caPath = typeof caInfo.path === 'string' ? caInfo.path : '.http-mitm-proxy/certs/ca.pem';
	const caDownload = caExists ? `<a href="/ca.pem">CAをダウンロード</a>` : '<span style="color:#666">HTTPS通信後にCAが生成されます</span>';
	const firstRunHtml = `<div class="card guide-card">
		<div style="font-weight:600; margin-bottom:8px;">初回ガイド</div>
		<ol class="guide-list">
			<li><strong>ブラウザ/OSのプロキシ</strong>を <code>127.0.0.1:8080</code> に設定します。</li>
			<li><strong>ログ対象</strong>を確認します。${loggingSummary}</li>
			<li><strong>HTTPSの中身を見る場合</strong>は <code>${escapeHtml(caPath)}</code> を信頼済みルートCAに登録します。${caDownload}</li>
			<li><strong>証明書ピンニング系アプリ</strong>はTLSバイパス対象に入れると、復号せずに通信を通せます。</li>
			<li><strong>通信後</strong>にこの画面を確認します。${refreshLabel}なので、新しいログは自動で反映されます。</li>
		</ol>
		<div class="scope-note">
			<div>${loggingSummary}</div>
			<div>${bodySummary}</div>
			<div>${fileSummary}</div>
			<div>${tlsBypassSummary}</div>
			<div>Windows登録例: <code>certutil -addstore -f root .\\.http-mitm-proxy\\certs\\ca.pem</code></div>
		</div>
	</div>`;

	const adminPanelHtml = `<div class="card">
		<div style="display:flex; gap:12px; align-items:center; justify-content:space-between; flex-wrap:wrap;">
			<div style="font-weight:600">管理</div>
			<div style="color:#5a6475; font-size:13px;">ブロックリストとログ操作</div>
		</div>
		<div style="margin-top:10px; color:#444;">ブロック対象ドメイン（1行1件）。保存するとすぐプロキシに反映されます。</div>
		<form method="post" action="/settings/blocking" style="margin-top:10px;">
			${csrfInput}
			<textarea name="blockDomains" rows="6" style="width:100%; box-sizing:border-box;">${escapeHtml(
				blocklistText
			)}</textarea>
			<div style="margin-top:10px; display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
				<button type="submit">保存</button>
				<span style="color:#444">現在の件数: ${escapeHtml(String(blockDomains.length))}</span>
			</div>
		</form>
		<form method="post" action="/settings/logs/clear" style="margin-top:10px;" onsubmit="return confirm('アクセスログを空にします。元に戻せません。');">
			${csrfInput}
			<label style="display:block; max-width:360px;">
				<span>ログ削除の確認（<code>CLEAR</code> と入力）</span>
				<input name="confirmClear" autocomplete="off" placeholder="CLEAR" />
			</label>
			<button type="submit">アクセスログを削除</button>
			<span style="color:#444; margin-left:8px;">削除前に必要なログは <code>data/access.log.jsonl</code> を保管してください。</span>
		</form>
	</div>`;

	const settingsPanelHtml = `<div class="card">
		<div style="font-weight:600; margin-bottom:8px;">取得設定</div>
		<div class="meta">ここで保存した内容は <code>config.local.json</code> に保存され、プロキシへ即時反映されます。</div>
		<form method="post" action="/settings/capture" class="settings-grid">
			${csrfInput}
			<label>
				<span>ログ対象モード</span>
				<select name="filteringMode">
					<option value="allowlist"${configSettings.filteringMode === 'allowlist' ? ' selected' : ''}>allowlist</option>
					<option value="all"${configSettings.filteringMode === 'all' ? ' selected' : ''}>all</option>
				</select>
			</label>
			<label>
				<span>ログ対象ドメイン（1行1件）</span>
				<textarea name="filteringDomains" rows="4">${escapeHtml((configSettings.filteringDomains || []).join('\n'))}</textarea>
			</label>
			<label>
				<span>本文取得対象ドメイン（空なら全ドメイン）</span>
				<textarea name="bodyCaptureDomains" rows="4">${escapeHtml((configSettings.bodyCaptureDomains || []).join('\n'))}</textarea>
			</label>
			<label>
				<span>ファイル保存対象ドメイン（空なら全ドメイン）</span>
				<textarea name="fileCaptureDomains" rows="4">${escapeHtml((configSettings.fileCaptureDomains || []).join('\n'))}</textarea>
			</label>
			<label>
				<span>TLSバイパス対象ドメイン（1行1件）</span>
				<textarea name="tlsBypassDomains" rows="4">${escapeHtml((configSettings.tlsBypassDomains || []).join('\n'))}</textarea>
			</label>
			<label>
				<span>本文保存上限 bytes</span>
				<input name="maxBodyBytes" type="number" min="0" value="${escapeHtml(String(configSettings.maxBodyBytes || 0))}" />
			</label>
			<label>
				<span>ログローテーション上限 bytes（0で無効）</span>
				<input name="loggingMaxBytes" type="number" min="0" value="${escapeHtml(String(configSettings.loggingMaxBytes || 0))}" />
			</label>
			<label class="check">
				<input type="checkbox" name="captureRequestBody" value="1"${configSettings.captureRequestBody ? ' checked' : ''} />
				<span>リクエスト本文</span>
			</label>
			<label class="check">
				<input type="checkbox" name="captureResponseBody" value="1"${configSettings.captureResponseBody ? ' checked' : ''} />
				<span>レスポンス本文</span>
			</label>
			<label class="check">
				<input type="checkbox" name="captureRequestFiles" value="1"${configSettings.captureRequestFiles ? ' checked' : ''} />
				<span>リクエスト画像ファイル</span>
			</label>
			<label class="check">
				<input type="checkbox" name="captureResponseFiles" value="1"${configSettings.captureResponseFiles ? ' checked' : ''} />
				<span>レスポンス画像ファイル</span>
			</label>
			<label class="check">
				<input type="checkbox" name="tlsBypassEnabled" value="1"${configSettings.tlsBypassEnabled !== false ? ' checked' : ''} />
				<span>証明書ピンニング系アプリをTLSバイパス</span>
			</label>
			<div style="display:flex; align-items:end;">
				<button type="submit">設定を保存</button>
			</div>
		</form>
	</div>`;

	const methodOptions = ['', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'CONNECT', 'OPTIONS', 'HEAD']
		.map((m) => {
			const selected = String(filters.method || '') === m ? ' selected' : '';
			return `<option value="${escapeHtml(m)}"${selected}>${escapeHtml(m || 'すべて')}</option>`;
		})
		.join('');

	const filterPanelHtml = `<div class="card">
		<div style="display:flex; gap:12px; align-items:center; justify-content:space-between; flex-wrap:wrap;">
			<div style="font-weight:600">フィルタ</div>
			${hasFilters ? `<a href="/">フィルタ解除</a>` : ''}
		</div>
		<form method="get" action="/" class="filter-grid" style="margin-top:10px;">
			<label>
				<span>キーワード</span>
				<input name="q" value="${escapeHtml(filters.q || '')}" placeholder="URL / ドメイン / Content-Type" />
			</label>
			<label>
				<span>ドメイン</span>
				<input name="domain" value="${escapeHtml(filters.domain || '')}" placeholder="example.com" />
			</label>
			<label>
				<span>メソッド</span>
				<select name="method">${methodOptions}</select>
			</label>
			<label>
				<span>ステータス</span>
				<input name="status" value="${escapeHtml(filters.status || '')}" placeholder="200 / 4 / 403" />
			</label>
			<label class="check">
				<input type="checkbox" name="pii" value="1"${filters.onlyPii ? ' checked' : ''} />
				<span>PIIのみ</span>
			</label>
			<label class="check">
				<input type="checkbox" name="phishing" value="1"${filters.onlyPhishing ? ' checked' : ''} />
				<span>フィッシング警告のみ</span>
			</label>
			<label class="check">
				<input type="checkbox" name="blocked" value="1"${filters.onlyBlocked ? ' checked' : ''} />
				<span>ブロックのみ</span>
			</label>
			<label class="check">
				<input type="checkbox" name="files" value="1"${filters.onlyFiles ? ' checked' : ''} />
				<span>ファイルありのみ</span>
			</label>
			<div style="display:flex; align-items:end;">
				<button type="submit">適用</button>
			</div>
		</form>
	</div>`;

	const refreshPanelHtml = `<div class="meta toolbar">
		<span>${escapeHtml(refreshLabel)}</span>
		<a href="${escapeHtml(refreshToggleHref)}">${autoRefreshEnabled ? '一時停止' : '再開'}</a>
		<a href="/">今すぐ更新</a>
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
			const piiRowClass = entryHasPii(e) ? ' class="pii-row"' : '';
			const statusBadges = renderStatusBadges(e);
			const uploadedFiles = renderUploadedFiles(e);
			const multipartMeta = renderMultipartMeta(e);
			const reqBodyCell = `${uploadedFiles}${multipartMeta}${renderBodyCell(e, 'request', dashId)}`;
			const resBodyCell = renderBodyCell(e, 'response', dashId);
			return `<tr${piiRowClass}>
				<td>${ts}</td>
				<td>${domain}</td>
				<td>${method}</td>
				<td>${status}</td>
				<td style="word-break:break-all">${statusBadges}${piiWarnings}<div>${url}</div></td>
				<td>${reqBodyCell}</td>
				<td>${resBodyCell}</td>
			</tr>`;
		})
		.join('');

	const metricItems = [
		['表示中', entries.length, '現在のフィルタ結果'],
		['全ログ', totalEntries, '読み込み済み件数'],
		['PII', countDashboardEntries(entries, entryHasPii), '個人情報を検知'],
		['フィッシング', countDashboardEntries(entries, (entry) => entry && entry.phishingWarning === true), '警告対象URL'],
		['ブロック', countDashboardEntries(entries, (entry) => entry && entry.blocked === true), '遮断済み通信'],
		['ファイル', countDashboardEntries(entries, entryHasSavedFile), '保存済み本文/添付'],
	];
	const metricsHtml = `<section class="metric-grid" aria-label="ログ概要">
		${metricItems
			.map(
				([label, value, hint]) => `<div class="metric-card">
					<div class="metric-label">${escapeHtml(label)}</div>
					<div class="metric-value">${escapeHtml(String(value))}</div>
					<div class="metric-hint">${escapeHtml(hint)}</div>
				</div>`
			)
			.join('')}
	</section>`;

	return `<!doctype html>
<html lang="ja">
	<head>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<title>プロキシログ</title>
		<style>
			:root {
				color-scheme: light;
				--bg: #f6f7f9;
				--panel: #fff;
				--line: #d9dee7;
				--line-soft: #e8ebf0;
				--text: #172033;
				--muted: #5a6475;
				--accent: #0f766e;
				--accent-soft: #e8f5f3;
				--danger: #b42318;
				--warn: #b26a00;
			}
			* { box-sizing: border-box; }
			body {
				font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
				margin: 0;
				background: var(--bg);
				color: var(--text);
				line-height: 1.55;
			}
			.page { max-width: 1440px; margin: 0 auto; padding: 20px; }
			.topbar { display: flex; justify-content: space-between; align-items: center; gap: 16px; margin-bottom: 16px; }
			.brand-title { margin: 0; font-size: 22px; line-height: 1.2; }
			.brand-subtitle { margin: 4px 0 0; color: var(--muted); font-size: 13px; }
			.nav-actions { display:flex; gap: 8px; flex-wrap: wrap; align-items: center; }
			.card {
				background: var(--panel);
				border: 1px solid var(--line);
				border-radius: 8px;
				padding: 14px;
				margin: 0 0 14px 0;
				box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
			}
			.metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 14px; }
			.metric-card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 12px; }
			.metric-label { color: var(--muted); font-size: 12px; font-weight: 700; }
			.metric-value { font-size: 28px; font-weight: 750; line-height: 1.15; margin-top: 4px; }
			.metric-hint { color: var(--muted); font-size: 12px; margin-top: 2px; }
			input, select, textarea {
				padding: 8px 10px;
				box-sizing: border-box;
				border: 1px solid var(--line);
				border-radius: 6px;
				background: #fff;
				color: var(--text);
			}
			input:focus, select:focus, textarea:focus { outline: 2px solid rgba(15, 118, 110, 0.22); border-color: var(--accent); }
			button, .button, .nav-actions a {
				display: inline-flex;
				align-items: center;
				justify-content: center;
				min-height: 34px;
				border: 1px solid var(--line);
				border-radius: 6px;
				padding: 7px 10px;
				background: #fff;
				color: var(--text);
				text-decoration: none;
				font-weight: 650;
				cursor: pointer;
			}
			button:hover, .button:hover, .nav-actions a:hover { border-color: var(--accent); background: var(--accent-soft); }
			label span { display: block; margin-bottom: 4px; color: var(--muted); font-size: 13px; }
			.filter-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; align-items: end; }
			.filter-grid label input, .filter-grid label select { width: 100%; }
			.filter-grid .check { display: flex; gap: 6px; align-items: center; padding-bottom: 8px; }
			.filter-grid .check span { display: inline; margin: 0; color: var(--text); }
			.settings-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; align-items: end; }
			.settings-grid input, .settings-grid select, .settings-grid textarea { width: 100%; box-sizing: border-box; }
			.settings-grid .check { display: flex; gap: 6px; align-items: center; padding-bottom: 8px; }
			.settings-grid .check input { width:auto; }
			.settings-grid .check span { display: inline; margin: 0; color: var(--text); }
			.health-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px; }
			.health-item { border: 1px solid #ddd; border-radius: 6px; padding: 8px; }
			.health-item.ok { border-left: 4px solid #087f23; }
			.health-item.warn { border-left: 4px solid #b26a00; }
			.guide-list { margin: 8px 0 0 20px; padding: 0; line-height: 1.6; }
			.scope-note { margin-top: 10px; color: #444; display: grid; gap: 4px; }
			.toolbar { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
			.badges { display:flex; gap:4px; flex-wrap:wrap; margin-bottom:4px; }
			.badge { display:inline-block; border-radius:999px; padding:1px 6px; font-size:12px; line-height:1.6; border:1px solid #ccc; color:#333; background:#f7f7f7; }
			.badge.danger { border-color:var(--danger); color:var(--danger); background:#fff5f5; }
			.badge.warn { border-color:var(--warn); color:#7a4700; background:#fff8e8; }
			.badge.neutral { border-color:#bbb; color:#333; background:#f7f7f7; }
			code { background: #f5f5f5; padding: 1px 4px; border-radius: 4px; }
			textarea { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
			.table-wrap {
				background: var(--panel);
				border: 1px solid var(--line);
				border-radius: 8px;
				overflow: auto;
				box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
			}
			table { width: 100%; border-collapse: collapse; }
			th, td { border-bottom: 1px solid var(--line-soft); padding: 10px; text-align: left; vertical-align: top; }
			th { position: sticky; top: 0; background: #f9fafb; color: var(--muted); font-size: 12px; z-index: 1; }
			tbody tr:hover { background: #fbfcfd; }
			.meta { margin: 0 0 12px 0; color: var(--muted); }
			.log-header { display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; margin: 6px 0 8px; }
			.log-count { color: var(--muted); font-size: 13px; }
			.pii-row td:first-child { border-left: 4px solid var(--danger); }
			/* Make the summary columns stand out (timestamp..URL), but keep body columns readable */
			.pii-row td:nth-child(-n+5) { color: var(--danger); font-weight: 600; }
			@media (max-width: 760px) {
				.page { padding: 12px; }
				.topbar { align-items: flex-start; flex-direction: column; }
				.metric-value { font-size: 24px; }
			}
		</style>
	</head>
	<body>
		<div class="page">
			<header class="topbar">
				<div>
					<h1 class="brand-title">SSL Inspection Proxy</h1>
					<p class="brand-subtitle">ローカルプロキシの通信ログ、検知、設定をまとめて確認できます。</p>
				</div>
				<nav class="nav-actions" aria-label="管理メニュー">
					<a href="/reports">レポート</a>
					<a href="/diagnostics">接続診断</a>
					<a href="/audit">監査ログ</a>
					${authEnabled ? `<a href="/logout">ログアウト</a>` : ''}
				</nav>
			</header>
			${metricsHtml}
		${healthHtml}
		${firstRunHtml}
		${adminPanelHtml}
		${settingsPanelHtml}
		${filterPanelHtml}
		${messageHtml}
		${refreshPanelHtml}
		<p class="meta">最新 ${escapeHtml(String(totalEntries))} 件中 ${escapeHtml(String(entries.length))} 件を表示</p>
		<div class="table-wrap">
		<table>
			<thead>
				<tr>
					<th>時刻</th>
					<th>ドメイン</th>
					<th>メソッド</th>
					<th>状態</th>
					<th>URL</th>
					<th>リクエスト本文</th>
					<th>レスポンス本文</th>
				</tr>
			</thead>
			<tbody>
				${rows}
			</tbody>
		</table>
		</div>
		</div>
		${autoRefreshEnabled ? `<script>
			window.setTimeout(function () {
				if (document.visibilityState === 'visible') window.location.reload();
			}, 5000);
		</script>` : ''}
	</body>
</html>`;
}

// PII詳細ページ（/entry/:id/pii）のHTMLを生成する。
// - wantReveal=1 のとき、生の一致候補（raw）も表示する（ただし authEnabled のときだけ）。
// - 生データはログ保存済みフィールドから再計算する（過去ログもオンデマンド再スキャンできる）。
function getPiiTypeDetails(entry) {
	const types = [
		{
			key: 'Email',
			label: 'メール',
			mask: maskEmail,
			compute: computeEmailMatchesFromLogEntry,
		},
		{
			key: 'Card',
			label: 'カード',
			mask: maskCardNumber,
			compute: computeCardMatchesFromLogEntry,
		},
		{
			key: 'Phone',
			label: '電話番号',
			mask: maskPhoneNumber,
			compute: computePhoneMatchesFromLogEntry,
		},
	];
	return types.map((type) => {
		const prefix = `pii${type.key}`;
		const detected = entry && entry[`${prefix}Detected`] === true;
		const count = typeof entry[`${prefix}Count`] === 'number' ? entry[`${prefix}Count`] : detected ? 1 : 0;
		const where = [
			entry && entry[`${prefix}InUrl`] ? 'url' : '',
			entry && (entry[`${prefix}InRequestBody`] || entry[`${prefix}InBody`]) ? 'request-body' : '',
			entry && entry[`${prefix}InResponse`] ? 'response' : '',
			entry && entry[`${prefix}InFormFields`] ? 'form' : '',
		]
			.filter(Boolean)
			.join(', ');
		let maskedSamples = Array.isArray(entry && entry[`${prefix}Samples`]) ? entry[`${prefix}Samples`] : [];
		if (detected && maskedSamples.length === 0) {
			try {
				maskedSamples = type.compute(entry).slice(0, 5).map(type.mask);
			} catch {
				maskedSamples = [];
			}
		}
		return { ...type, detected, count, where, maskedSamples };
	});
}

function renderPiiDetailHtml({ entry, idParam, index, authEnabled, wantReveal }) {
	const canReveal = authEnabled === true;
	const revealBlockedNote = wantReveal && !canReveal ? 'ダッシュボード認証が無効なため、生データ表示は利用できません。' : '';
	const idForUrl = encodeURIComponent(String(idParam || index));
	const details = getPiiTypeDetails(entry);
	const anyDetected = details.some((d) => d.detected);
	const revealLink = anyDetected
		? canReveal
					? `<a href="/entry/${idForUrl}/pii?reveal=1" rel="noopener noreferrer">生の一致候補を表示</a>`
			: `<span style="color:#444">(生データ表示にはダッシュボード認証を有効にしてください)</span>`
		: '';

	const sections = details
		.map((detail) => {
			const maskedHtml = detail.maskedSamples.length
				? `<pre style="white-space:pre-wrap; word-break:break-word;">${escapeHtml(JSON.stringify(detail.maskedSamples, null, 2))}</pre>`
				: `<div style="color:#444">(マスク済みサンプルなし)</div>`;
			let rawHtml = '';
			if (wantReveal && canReveal && detail.detected) {
				let rawMatches = [];
				try {
					rawMatches = detail.compute(entry);
				} catch {
					rawMatches = [];
				}
				rawHtml = rawMatches.length
					? `<h3>生の一致候補</h3><pre style="white-space:pre-wrap; word-break:break-word;">${escapeHtml(JSON.stringify(rawMatches, null, 2))}</pre>`
					: `<h3>生の一致候補</h3><div style="color:#444">(保存済みフィールドから一致候補を再検出できませんでした。本文が切り詰められたか、エンコードされている可能性があります)</div>`;
			}
			return `<section class="pii-section">
				<h2>${escapeHtml(detail.label)}</h2>
				<div class="meta">状態: ${detail.detected ? `検出 (件数=${escapeHtml(String(detail.count))}${detail.where ? `, 場所=${escapeHtml(detail.where)}` : ''})` : '未検出'}</div>
				<h3>マスク済みサンプル</h3>
				${maskedHtml}
				${rawHtml}
			</section>`;
		})
		.join('');

	return `<!doctype html>
<html lang="ja">
	<head>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<title>PII 詳細</title>
		<style>
			body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 16px; }
			.card { border: 1px solid #ddd; border-radius: 8px; padding: 12px; }
			.meta { color: #444; margin: 0 0 10px 0; }
			h2 { margin: 14px 0 8px 0; font-size: 16px; }
			h3 { margin: 10px 0 6px 0; font-size: 14px; }
			.pii-section { border-top:1px solid #ddd; padding-top:10px; margin-top:10px; }
		</style>
	</head>
	<body>
			<div class="meta"><a href="/">&larr; 戻る</a></div>
		<div class="card">
			<div class="meta">ドメイン: ${escapeHtml(String(entry.domain || ''))}</div>
			<div class="meta">url: <span style="word-break:break-all">${escapeHtml(String(entry.URL || ''))}</span></div>
			${revealBlockedNote ? `<div class="meta" style="color:#a00">${escapeHtml(revealBlockedNote)}</div>` : ''}
			${anyDetected ? `<div class="meta">${revealLink}</div>` : '<div class="meta">このログではPIIは検出されていません。</div>'}
			${sections}
		</div>
	</body>
</html>`;
}

function renderReportHtml(report) {
	const data = report && typeof report === 'object' ? report : {};
	const summary = data.summary && typeof data.summary === 'object' ? data.summary : {};
	const topDomains = Array.isArray(data.topDomains) ? data.topDomains : [];
	const methods = Array.isArray(data.methods) ? data.methods : [];
	const statuses = Array.isArray(data.statuses) ? data.statuses : [];
	const recentWarnings = Array.isArray(data.recentWarnings) ? data.recentWarnings : [];

	function numberCell(value) {
		return escapeHtml(String(Number.isFinite(value) ? value : 0));
	}

	function countTable(rows, emptyText) {
		if (!rows.length) return `<p class="meta">${escapeHtml(emptyText || 'No data')}</p>`;
		return `<table>
			<thead><tr><th>項目</th><th>件数</th></tr></thead>
			<tbody>
				${rows
					.map(
						(row) => `<tr>
							<td>${escapeHtml(row.label || '')}</td>
							<td>${numberCell(row.count)}</td>
						</tr>`
					)
					.join('')}
			</tbody>
		</table>`;
	}

	const warningRows = recentWarnings.length
		? recentWarnings
				.map((entry) => {
					const flags = [
						entry.phishing ? 'phishing' : '',
						entry.pii ? 'PII' : '',
						entry.blocked ? 'blocked' : '',
					]
						.filter(Boolean)
						.join(', ');
					return `<tr>
						<td>${escapeHtml(entry.timestamp || '')}</td>
						<td>${escapeHtml(entry.domain || '')}</td>
						<td>${escapeHtml(entry.method || '')}</td>
						<td>${escapeHtml(entry.status || '')}</td>
						<td>${escapeHtml(flags || '-')}</td>
						<td style="word-break:break-all">${escapeHtml(entry.url || '')}</td>
					</tr>`;
				})
				.join('')
		: `<tr><td colspan="6" class="meta">警告ログはありません</td></tr>`;

	return `<!doctype html>
<html lang="ja">
	<head>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<title>アクセスログレポート</title>
		<style>
			body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 16px; line-height: 1.6; }
			.card { border: 1px solid #ddd; border-radius: 8px; padding: 12px; margin: 0 0 12px 0; }
			.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; }
			.metric { border: 1px solid #ddd; border-radius: 6px; padding: 10px; background: #fafafa; }
			.metric strong { display: block; font-size: 22px; }
			.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }
			table { width: 100%; border-collapse: collapse; }
			th, td { border-bottom: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
			code { background: #f5f5f5; padding: 1px 4px; border-radius: 4px; }
			.meta { color:#444; }
		</style>
	</head>
	<body>
		<div class="meta"><a href="/">&larr; 戻る</a></div>
		<h1>アクセスログレポート</h1>
		<p class="meta">生成日時 <code>${escapeHtml(data.generatedAt || '')}</code></p>
		<div class="card summary-grid">
			<div class="metric"><span>総ログ数</span><strong>${numberCell(summary.total)}</strong></div>
			<div class="metric"><span>HTTPS</span><strong>${numberCell(summary.https)}</strong></div>
			<div class="metric"><span>フィッシング警告</span><strong>${numberCell(summary.phishing)}</strong></div>
			<div class="metric"><span>PII警告</span><strong>${numberCell(summary.pii)}</strong></div>
			<div class="metric"><span>ブロック</span><strong>${numberCell(summary.blocked)}</strong></div>
			<div class="metric"><span>保存ファイル</span><strong>${numberCell(summary.files)}</strong></div>
		</div>
		<div class="card summary-grid">
			<div class="metric"><span>メール</span><strong>${numberCell(summary.email)}</strong></div>
			<div class="metric"><span>カード番号</span><strong>${numberCell(summary.card)}</strong></div>
			<div class="metric"><span>電話番号</span><strong>${numberCell(summary.phone)}</strong></div>
		</div>
		<div class="grid">
			<div class="card">
				<h2>上位ドメイン</h2>
				${countTable(topDomains, 'ドメインはありません')}
			</div>
			<div class="card">
				<h2>メソッド</h2>
				${countTable(methods, 'メソッドはありません')}
			</div>
			<div class="card">
				<h2>ステータス分類</h2>
				${countTable(statuses, 'ステータスはありません')}
			</div>
		</div>
		<div class="card">
			<h2>最近の警告</h2>
			<table>
				<thead><tr><th>時刻</th><th>ドメイン</th><th>メソッド</th><th>状態</th><th>種別</th><th>URL</th></tr></thead>
				<tbody>${warningRows}</tbody>
			</table>
		</div>
	</body>
</html>`;
}

function renderDiagnosticsHtml(options) {
	const opts = options && typeof options === 'object' ? options : {};
	const dashboardUrl = typeof opts.dashboardUrl === 'string' ? opts.dashboardUrl : 'http://127.0.0.1:3001';
	const proxyAddress = typeof opts.proxyAddress === 'string' ? opts.proxyAddress : '127.0.0.1:8080';
	const caInfo = opts.caInfo && typeof opts.caInfo === 'object' ? opts.caInfo : {};
	const lastProxyCheck = opts.lastProxyCheck && typeof opts.lastProxyCheck === 'object' ? opts.lastProxyCheck : null;
	const tlsBypassDomains = Array.isArray(opts.tlsBypassDomains) ? opts.tlsBypassDomains : [];
	const proxyCheckUrl = 'http://proxy.test/ssl-inspection-proxy-check';
	const httpsCheckUrl = 'https://proxy.test/ssl-inspection-proxy-check';
	const checkedAt = lastProxyCheck && lastProxyCheck.timestamp ? escapeHtml(lastProxyCheck.timestamp) : '';
	const checkedScheme = lastProxyCheck && lastProxyCheck.isSSL ? 'HTTPS' : 'HTTP';
	const lastCheckHtml = lastProxyCheck
		? `<div class="status ok">直近の診断アクセス: OK (${checkedScheme}, ${checkedAt})</div>`
		: '<div class="status warn">まだ診断アクセスは記録されていません。下のチェックURLを開いてください。</div>';
	const caHtml = caInfo.exists
		? `<div class="status ok">ローカルCA: 生成済み <code>${escapeHtml(caInfo.path || '.http-mitm-proxy/certs/ca.pem')}</code></div>`
		: '<div class="status warn">ローカルCA: 未生成です。HTTPS通信を一度プロキシ経由で開くと生成されます。</div>';
	const tlsBypassHtml = tlsBypassDomains.length
		? tlsBypassDomains.map((domain) => `<code>${escapeHtml(domain)}</code>`).join(', ')
		: '<span style="color:#666">未設定</span>';

	return `<!doctype html>
<html lang="ja">
	<head>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<title>接続診断</title>
		<style>
			body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 16px; line-height: 1.6; }
			.card { border: 1px solid #ddd; border-radius: 8px; padding: 12px; margin: 0 0 12px 0; }
			.status { border-left: 4px solid #bbb; padding: 8px 10px; margin: 8px 0; background: #fafafa; }
			.status.ok { border-left-color: #087f23; }
			.status.warn { border-left-color: #b26a00; }
			code { background: #f5f5f5; padding: 1px 4px; border-radius: 4px; }
			.actions { display:flex; gap:10px; flex-wrap:wrap; margin-top:10px; }
			.button { display:inline-block; border:1px solid #bbb; border-radius:6px; padding:7px 10px; color:#111; text-decoration:none; background:#fff; }
			.meta { color:#444; }
		</style>
	</head>
	<body>
		<div class="meta"><a href="/">&larr; 戻る</a></div>
		<h1>接続診断</h1>
		<div class="card">
			<h2>基本設定</h2>
			<div>ダッシュボード: <code>${escapeHtml(dashboardUrl)}</code></div>
			<div>ブラウザ/OSに設定するプロキシ: <code>${escapeHtml(proxyAddress)}</code></div>
			${caHtml}
		</div>
		<div class="card">
			<h2>プロキシ経由チェック</h2>
			${lastCheckHtml}
			<p class="meta">HTTPチェックは「ブラウザがプロキシを使っているか」を確認します。HTTPSチェックはそれに加えて「ローカルCAを信頼できているか」を確認します。</p>
			<div class="actions">
				<a class="button" href="${proxyCheckUrl}" target="_blank" rel="noopener noreferrer">HTTPチェックを開く</a>
				<a class="button" href="${httpsCheckUrl}" target="_blank" rel="noopener noreferrer">HTTPSチェックを開く</a>
			</div>
			<p class="meta">開いたあと、このページを再読み込みしてください。成功していれば直近の診断アクセスがOKになります。</p>
		</div>
		<div class="card">
			<h2>TLSバイパス</h2>
			<div>対象: ${tlsBypassHtml}</div>
			<p class="meta">Spotifyなど証明書ピンニングが強いアプリは、ここに入っているドメインでは復号せずに通信を通します。</p>
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
	renderDiagnosticsHtml,
	renderReportHtml,
	renderPiiDetailHtml,
	computeDashboardEntryKey,
};
