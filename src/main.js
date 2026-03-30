/*
メモ
Web閲覧監視プロキシ（エントリポイント）

目的
- プロキシ本体（http-mitm-proxy）を起動し、HTTP/HTTPS を中継する
- リクエスト/レスポンスのメタ情報（URL/メソッド/ステータス等）を収集して JSONL に追記する
- （サイズ・MIME等の条件に応じて）本文を収集し、テキスト化して PII 検出に回す
- multipart/form-data のアップロード（例: 画像）をファイルに保存し、ダッシュボードから参照できるURLをログに残す
- 設定に応じて allowlist / blocklist により通信をブロックする
- ダッシュボード（Express）も同一プロセスで起動する（実装は `src/dashboard/server.js`）

原理（要点）
- 明示プロキシとして動作するため、端末側ブラウザは「プロキシサーバ」を設定してこのプロキシに接続する。
- HTTPS は CONNECT トンネルを MITM で復号し、通常のHTTPリクエスト/レスポンスとしてイベントフックできる。
- 本文は“無制限に読む”とメモリ/プライバシーの問題が出るため、収集量を制限し、
	テキストっぽい場合だけベストエフォートにデコードして `src/pii.js` の検出ロジックに渡す。

責務分割（このファイルに残す理由）
- MITMのイベント配線、ストリーム収集、ファイル保存など「プロキシのI/O側」はここに集約
- HTML生成/認証/ルーティングなど「ダッシュボード側」は `src/dashboard/*` に分離
*/

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { PassThrough } = require('node:stream');
const { URL } = require('node:url');

const Busboy = require('busboy');
const { Proxy } = require('http-mitm-proxy');

const { loadConfig } = require('./config');
const { appendJsonl } = require('./logStore');
const { startDashboard } = require('./dashboard/server');
const { parseContentType, isTextLikeMime, looksBinary, decodeTextBodyForPii } = require('./httpBody');
const { buildEmailPiiFields } = require('./pii');
const { configurePolicyStore, getBlockDomains } = require('./policyStore');

// このプロトタイプがやること（ざっくり）
// 1) 従業員端末のブラウザに「明示プロキシ」を設定してもらう
// 2) プロキシがHTTP/HTTPSを中継する（HTTPSはMITMで中身を見られる）
// 3) アクセス情報（timestamp/domain/url/method/status）をJSONLで永続化
// 4) ダッシュボード（Web）でログ一覧を閲覧
// 5) 設定されたドメインはブロック（例: tiktok.com）

// 共通: ドメイン判定
function normalizeHostname(hostname) {
	return (hostname || '').toLowerCase().replace(/\.$/, '');
}

function getHostnameFromCtx(ctx) {
	// onError でどの通信が落ちたか分かるように、可能な範囲でHostを推定する
	try {
		if (!ctx) return '';
		if (ctx.clientToProxyRequest && ctx.clientToProxyRequest.headers) {
			return normalizeHostname(ctx.clientToProxyRequest.headers.host);
		}
	} catch {
		// ignore
	}
	return '';
}

// ホスト名がルールにマッチするか（例: rule "google.com" は "google.com" や "www.google.com" にマッチするが "evilgoogle.com" にはマッチしない）
function hostnameMatches(hostname, rule) {
	// ホスト名の正規化: 小文字化、末尾のドット削除
	const host = normalizeHostname(hostname);
	const r = normalizeHostname(rule);
	if (!host || !r) return false;
	return host === r || host.endsWith(`.${r}`);
}

function isBlocked(hostname, config) {
	// 現在のブロック対象（ダッシュボードから更新されうる）に一致したらブロック
	// - policyStore は起動時に config.blocking.domains をデフォルトとして設定される
	// - ダッシュボードの保存操作で in-memory の一覧が更新され、ここにも即時反映される
	const rules = getBlockDomains();
	for (const rule of rules) {
		if (hostnameMatches(hostname, rule)) return true;
	}
	return false;
}

function shouldLog(hostname, config) {
	// filtering.mode:
	// - "all": 全通信をログ対象
	// - "allowlist": domainsに一致する通信だけログ対象
	const filtering = config && config.filtering ? config.filtering : { mode: 'all', domains: [] };
	if (filtering.mode === 'allowlist') {
		const rules = Array.isArray(filtering.domains) ? filtering.domains : [];
		for (const rule of rules) {
			if (hostnameMatches(hostname, rule)) return true;
		}
		return false;
	}
	return true;
}

function shouldCaptureBody(hostname, config) {
	// ボディは機微情報を含みやすいので、デフォルトでは対象ドメインを絞る。
	// - inspection.bodyCaptureDomains があればそれを使用
	// - なければ filtering.domains を使用（課題の対象: google.com / yahoo.co.jp）
	const inspection = config && config.inspection ? config.inspection : {};
	const explicit = Array.isArray(inspection.bodyCaptureDomains) ? inspection.bodyCaptureDomains : null;
	const fallback =
		config && config.filtering && Array.isArray(config.filtering.domains) ? config.filtering.domains : [];
	const rules = explicit !== null ? explicit : fallback;
	if (!Array.isArray(rules) || rules.length === 0) return true;
	for (const rule of rules) {
		if (hostnameMatches(hostname, rule)) return true;
	}
	return false;
}

function shouldCaptureFiles(hostname, config) {
	// ファイル保存（画像など）はさらに機微になりやすいので、デフォルトでは対象ドメインを絞る。
	// - inspection.fileCaptureDomains があればそれを使用
	// - なければ inspection.bodyCaptureDomains、さらに無ければ filtering.domains を使用
	const inspection = config && config.inspection ? config.inspection : {};
	const explicit = Array.isArray(inspection.fileCaptureDomains) ? inspection.fileCaptureDomains : null;
	const fallback = Array.isArray(inspection.bodyCaptureDomains)
		? inspection.bodyCaptureDomains
		: config && config.filtering && Array.isArray(config.filtering.domains)
			? config.filtering.domains
			: [];
	const rules = explicit !== null ? explicit : fallback;
	if (!Array.isArray(rules) || rules.length === 0) return true;
	for (const rule of rules) {
		if (hostnameMatches(hostname, rule)) return true;
	}
	return false;
}

function buildLogEntry({ url, method, status, hostname }) {
	return {
		timestamp: new Date().toISOString(),
		domain: hostname,
		URL: url,
		method,
		status,
	};
}

// NOTE: Body decoding / MIME heuristics and PII detection have been split into modules:
// - ./httpBody
// - ./pii

// ボディを一定量まで収集するユーティリティ
function createBodyCollector(maxBytes) {
	const limit = Number.isFinite(maxBytes) ? Math.max(0, maxBytes) : 0;
	let totalBytes = 0;
	let truncated = false;
	const chunks = [];
	let buffered = 0;

	function push(chunk) {
		if (!chunk || chunk.length === 0) return;
		totalBytes += chunk.length;
		// limit=0 は「バッファしない（＝保存しない）で、サイズだけ数える」モード
		if (limit === 0) return;
		if (buffered >= limit) {
			truncated = true;
			return;
		}
		const remaining = limit - buffered;
		if (chunk.length <= remaining) {
			chunks.push(chunk);
			buffered += chunk.length;
			return;
		}
		chunks.push(chunk.subarray(0, remaining));
		buffered += remaining;
		truncated = true;
	}

	function getBuffer() {
		if (chunks.length === 0) return Buffer.alloc(0);
		return Buffer.concat(chunks);
	}

	function getMeta() {
		return { totalBytes, bufferedBytes: buffered, truncated };
	}

	function toLogFields(prefix, contentTypeHeader, contentEncodingHeader) {
		const { mime, charset } = parseContentType(contentTypeHeader);
		const buf = getBuffer();
		const encoding = String(contentEncodingHeader || '').toLowerCase();
		const isText = isTextLikeMime(mime) && !looksBinary(buf);

		const fields = {
			[`${prefix}ContentType`]: mime || '',
			[`${prefix}Charset`]: charset || '',
			[`${prefix}ContentEncoding`]: encoding || '',
			[`${prefix}BodyBytes`]: totalBytes,
			[`${prefix}BodyTruncated`]: truncated,
		};

		if (buf.length === 0) return fields;

		if (isText) {
			fields[`${prefix}BodyText`] = buf.toString('utf8');
		} else {
			fields[`${prefix}BodyBase64`] = buf.toString('base64');
		}
		return fields;
	}

	return { push, toLogFields, getBuffer, getMeta };
}

// ファイル保存用のユーティリティ
function ensureDir(dirPath) {
	fs.mkdirSync(dirPath, { recursive: true });
}

function buildSavedFileName(prefix, mimeType) {
	const ts = new Date().toISOString().replaceAll(':', '').replaceAll('.', '').replaceAll('-', '');
	const rand = crypto.randomBytes(6).toString('hex');
	const mime = String(mimeType || '').toLowerCase();
	let ext = 'bin';
	if (mime === 'image/jpeg') ext = 'jpg';
	else if (mime === 'image/png') ext = 'png';
	else if (mime === 'image/gif') ext = 'gif';
	else if (mime === 'image/webp') ext = 'webp';
	else if (mime.startsWith('image/')) ext = mime.slice('image/'.length).replaceAll(/[^a-z0-9]+/g, '') || 'img';
	return `${prefix}_${ts}_${rand}.${ext}`;
}

function buildFileUrl(fileName) {
	return `/files/${encodeURIComponent(String(fileName || ''))}`;
}

function createMultipartImageCapture({ headers, saveDirAbs, maxFileBytes }) {
	const state = {
		fields: {},
		files: [],
		skippedFiles: [],
		completed: false,
		errors: [],
	};

	const bb = Busboy({ headers });

	bb.on('field', (name, value) => {
		if (!name) return;
		if (Object.prototype.hasOwnProperty.call(state.fields, name)) {
			const current = state.fields[name];
			state.fields[name] = Array.isArray(current) ? [...current, value] : [current, value];
			return;
		}
		state.fields[name] = value;
	});

	bb.on('file', (fieldname, file, info) => {
		const originalFilename = info && typeof info.filename === 'string' ? info.filename : '';
		const mimeType = info && typeof info.mimeType === 'string' ? info.mimeType : '';
		const mime = String(mimeType || '').toLowerCase();

		if (!mime.startsWith('image/')) {
			state.skippedFiles.push({ fieldname, originalFilename, mimeType, reason: 'not_image' });
			file.resume();
			return;
		}

		let bytes = 0;
		let exceeded = false;
		let writeError = '';
		const fileName = buildSavedFileName('req', mime);
		const absPath = path.join(saveDirAbs, fileName);
		ensureDir(path.dirname(absPath));
		const out = fs.createWriteStream(absPath);

		file.on('data', (chunk) => {
			bytes += chunk.length;
			if (!exceeded && Number.isFinite(maxFileBytes) && maxFileBytes > 0 && bytes > maxFileBytes) {
				exceeded = true;
				try {
					out.destroy();
				} catch {
					// ignore
				}
				try {
					fs.unlinkSync(absPath);
				} catch {
					// ignore
				}
				file.resume();
				return;
			}
			if (!exceeded) out.write(chunk);
		});

		file.on('error', (e) => {
			writeError = e && e.message ? e.message : String(e);
		});

		file.on('end', () => {
			try {
				out.end();
			} catch {
				// ignore
			}
			if (exceeded) {
				state.skippedFiles.push({ fieldname, originalFilename, mimeType, reason: 'too_large', maxFileBytes });
				return;
			}
			if (writeError) {
				try {
					fs.unlinkSync(absPath);
				} catch {
					// ignore
				}
				state.skippedFiles.push({ fieldname, originalFilename, mimeType, reason: 'write_error', error: writeError });
				return;
			}
			state.files.push({
				fieldname,
				originalFilename,
				mimeType,
				bytes,
				url: buildFileUrl(fileName),
			});
		});
	});

	bb.on('error', (e) => {
		state.errors.push(e && e.message ? e.message : String(e));
	});
	bb.on('close', () => {
		state.completed = true;
	});
	bb.on('finish', () => {
		state.completed = true;
	});

	const input = new PassThrough();
	input.pipe(bb);

	return {
		state,
		write(chunk) {
			input.write(chunk);
		},
		end() {
			input.end();
		},
	};
}

// HTMLエスケープとダッシュボード用のテキスト処理ロジック
function escapeHtml(s) {
	return String(s)
		.replaceAll('&', '&amp;')
		.replaceAll('<', '&lt;')
		.replaceAll('>', '&gt;')
		.replaceAll('"', '&quot;')
		.replaceAll("'", '&#39;');
}


// HTTPヘッダ名として有効かを判定する
function isValidHttpHeaderName(name) {
	// RFC 7230 token (tchar) 相当。スペース等が混じると Node が writeHead で落ちる。
	// https://www.rfc-editor.org/rfc/rfc7230#section-3.2.6
	return /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(String(name || ''));
}

// HTTPヘッダ名として無効なものを削除して、削除したヘッダ名のリストも返す
function sanitizeHeaderNames(headers) {
	if (!headers || typeof headers !== 'object') return { headers: {}, removed: [] };
	const removed = [];
	for (const key of Object.keys(headers)) {
		if (!isValidHttpHeaderName(key)) {
			removed.push(key);
			delete headers[key];
		}
	}
	return { headers, removed };
}

// ============================================================
// 通信検査プロキシ（HTTP/HTTPS MITM）
// ============================================================
function startMitmProxy(config) {
	// http-mitm-proxy が、
	// - HTTPはそのまま中継
	// - HTTPSは（必要なら）MITMして中身を見られる状態で中継
	const proxy = new Proxy();
	const logPath = config.logging.path;

	let warnedKeyMismatch = false;
	let warnedUpstreamCa = false;
	let clientResetCount = 0;
	let lastClientResetLogAt = 0;
	proxy.onError((ctx, err, kind) => {
		const host = getHostnameFromCtx(ctx);
		const code = err && err.code ? err.code : '';
		const message = err && err.message ? err.message : String(err);

		// Browsers frequently reset sockets (tab close/reload/timeouts). Logging every ECONNRESET can become noisy
		// and slow down the proxy when the dashboard or browser is under load.
		if (kind === 'HTTPS_CLIENT_ERROR' && code === 'ECONNRESET') {
			clientResetCount += 1;
			const now = Date.now();
			if (now - lastClientResetLogAt > 5000) {
				lastClientResetLogAt = now;
				console.warn(`Proxy: HTTPS_CLIENT_ERROR ECONNRESET (socket hang up) x${clientResetCount} (last ~5s)`);
				clientResetCount = 0;
			}
			return;
		}

		// When running in Docker or corporate networks, upstream TLS may be MITM'd by a company CA
		// that is trusted on the host OS but not inside the container.
		if (
			!warnedUpstreamCa &&
			kind === 'PROXY_TO_SERVER_REQUEST_ERROR' &&
			(code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || /unable to verify the first certificate/i.test(message))
		) {
			warnedUpstreamCa = true;
			console.error(
				'Hint: Upstream TLS verification failed. If you run this in Docker or behind a corporate SSL-inspection proxy, '
					+ 'the corporate root CA may not be trusted inside the container. '
					+ 'Try providing the CA via NODE_EXTRA_CA_CERTS (PEM) or installing it into the container OS trust store.'
			);
		}

		console.error('Proxy error:', kind, host ? `host=${host}` : '', code ? `code=${code}` : '', message);

		if (!warnedKeyMismatch && (code === 'ERR_OSSL_X509_KEY_VALUES_MISMATCH' || /key values mismatch/i.test(message))) {
			warnedKeyMismatch = true;
			console.error(
				'Hint: TLS cert/key cache may be corrupted. Stop the proxy, run `npm run clean:mitm`, then restart. '
					+ 'This wipes `.http-mitm-proxy/` (generated cert/key cache) and forces regeneration.'
			);
		}
	});

	// ホストレベルでのブロック判定（CONNECTリクエストに対して）
	proxy.onConnect((req, socket, head, callback) => {
		// ここで CONNECT をブロックすると、ブラウザ側では
		// "ERR_TUNNEL_CONNECTION_FAILED" のような分かりにくいエラーになりがち。
		//
		// CA を信頼している前提では、CONNECT は通しておき、
		// 実際のHTTPリクエスト段階（onRequest）でブロックページを返す方が
		// ユーザーにとって分かりやすいかも。
		callback();
	});

	proxy.onRequest((ctx, callback) => {
		// ctx は http-mitm-proxy が渡してくれる「この1リクエスト分のコンテキスト」
		// - ctx.clientToProxyRequest: ブラウザ → プロキシ へのリクエスト
		// - ctx.proxyToClientResponse: プロキシ → ブラウザ へのレスポンス（ここで403を返す等）
		// - ctx.onResponse(...): 外部サーバーからのレスポンスが返ったタイミングで呼ばれるフック
		// - ctx.isSSL: HTTPS(MITM)のとき true
		// ここでの「ブロック」はアプリ側(403)だが、
		// 「証明書を信頼していない」場合はブラウザがTLSエラーで止める（=プロキシの403ではない）。
		//
		//  onResponse の引数名を responseCtx に

		const inspection = config && config.inspection ? config.inspection : {};
		const maxBodyBytes = Number.isFinite(inspection.maxBodyBytes) ? inspection.maxBodyBytes : 32768;
		const maxFileBytes = Number.isFinite(inspection.maxFileBytes) ? inspection.maxFileBytes : 2 * 1024 * 1024;
		const fileSaveDir = typeof inspection.fileSaveDir === 'string' && inspection.fileSaveDir ? inspection.fileSaveDir : './data/files';
		const captureFiles = inspection.captureFiles === true;
		const captureRequestFiles = inspection.captureRequestFiles === true || captureFiles;
		const captureResponseFiles = inspection.captureResponseFiles === true || captureFiles;
		const captureRequestBody = inspection.captureRequestBody !== false;
		const captureResponseBody = inspection.captureResponseBody !== false;

		// ここで「ブロック判定」と「ログ記録のフック」を仕込む
		const req = ctx.clientToProxyRequest;
		const resToClient = ctx.proxyToClientResponse;
		const method = req.method || 'GET';
		const headers = req.headers || {};
		const hostname = normalizeHostname(headers.host);
		const captureBodiesForHost = shouldCaptureBody(hostname, config);
		const captureFilesForHost = shouldCaptureFiles(hostname, config);
		const reqContentTypeHeader = headers['content-type'] || headers['Content-Type'] || '';
		const { mime: reqMime } = parseContentType(reqContentTypeHeader);
		const isMultipartForm = reqMime === 'multipart/form-data';
		const scheme = ctx.isSSL ? 'https' : 'http';
		const requestPath = req.url || '/';
		let fullUrl;
		try {
			fullUrl = new URL(requestPath, `${scheme}://${hostname}`).toString();
		} catch {
			fullUrl = String(requestPath);
		}

		const requestBody = createBodyCollector(isMultipartForm && captureRequestFiles && captureFilesForHost ? 0 : maxBodyBytes);
		const responseTextBody = createBodyCollector(maxBodyBytes);
		const responseFileBody = createBodyCollector(maxFileBytes);
		let responseStatusCode;
		let responseHeaders = {};
		let responseIsImage = false;
		let multipartCapture = null;

		if (isMultipartForm && captureRequestFiles && captureFilesForHost) {
			try {
				multipartCapture = createMultipartImageCapture({
					headers,
					saveDirAbs: path.resolve(process.cwd(), fileSaveDir),
					maxFileBytes,
				});
			} catch (e) {
				multipartCapture = {
					state: { fields: {}, files: [], skippedFiles: [], completed: true, errors: [e && e.message ? e.message : String(e)] },
					write() {},
					end() {},
				};
			}
		}

		if ((captureRequestBody && captureBodiesForHost) || multipartCapture) {
			ctx.onRequestData((dataCtx, chunk, cb) => {
				try {
					requestBody.push(chunk);
					if (multipartCapture) multipartCapture.write(chunk);
				} catch {
					// ignore
				}
				cb(null, chunk);
			});
		}

		if (multipartCapture) {
			ctx.onRequestEnd((endReqCtx, cb) => {
				try {
					multipartCapture.end();
				} catch {
					// ignore
				}
				cb();
			});
		}

		if ((captureResponseBody && captureBodiesForHost) || (captureResponseFiles && captureFilesForHost)) {
			ctx.onResponseData((dataCtx, chunk, cb) => {
				try {
					if (responseIsImage && captureResponseFiles && captureFilesForHost) {
						responseFileBody.push(chunk);
					} else if (captureResponseBody && captureBodiesForHost) {
						responseTextBody.push(chunk);
					}
				} catch {
					// ignore
				}
				cb(null, chunk);
			});
		}

		// ブロック（HTTP/HTTPS共通）
		if (isBlocked(hostname, config)) {
			resToClient.writeHead(403, { 'content-type': 'text/html; charset=utf-8' });
			resToClient.end(`<!doctype html>
<html lang="ja">
	<head>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<title>Blocked</title>
		<style>
			body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }
			code { background: #f5f5f5; padding: 2px 6px; border-radius: 4px; }
		</style>
	</head>
	<body>
		<h1>このサイトへのアクセスはブロックされました</h1>
		<p>ドメイン: <code>${escapeHtml(hostname)}</code></p>
		<p>理由: Proxyのブロック設定に一致</p>
	</body>
</html>`);
			if (shouldLog(hostname, config)) {
				appendJsonl(
					logPath,
					Object.assign(
						buildLogEntry({ url: fullUrl, method, status: 403, hostname }),
						{ blocked: true, isSSL: Boolean(ctx.isSSL) }
					)
				);
			}
			return;
		}

		// レスポンスヘッダーのサニタイズ（不正なヘッダー名があると Node が writeHead でクラッシュする）
		ctx.onResponseHeaders((headersCtx, cb) => {
			try {
				const serverRes = headersCtx && headersCtx.serverToProxyResponse;
				if (serverRes && serverRes.headers) {
					const { removed } = sanitizeHeaderNames(serverRes.headers);
					if (removed.length > 0) {
						const host = getHostnameFromCtx(headersCtx) || hostname;
						console.warn(
							'Removed invalid response header names:',
							removed.join(', '),
							host ? `host=${host}` : ''
						);
					}
				}
			} catch {
				// ignore
			}
			cb();
		});

		// レスポンスが返ってきたタイミングで status を含めてログを保存
		ctx.onResponse((responseCtx, cb) => {
			// responseCtx も同じく「この通信分のコンテキスト」
			// （レスポンスが到着した段階なので statusCode 等が参照できる）
			const serverRes = responseCtx.serverToProxyResponse;
			responseStatusCode = serverRes ? serverRes.statusCode : undefined;
			responseHeaders = serverRes && serverRes.headers ? serverRes.headers : {};
			try {
				const resContentType = responseHeaders['content-type'] || responseHeaders['Content-Type'] || '';
				const { mime } = parseContentType(resContentType);
				responseIsImage = String(mime || '').toLowerCase().startsWith('image/');
			} catch {
				responseIsImage = false;
			}

			cb();
		});

		// レスポンスがクライアントに返し終わったタイミングでログを確定して保存
		ctx.onResponseEnd((endCtx, cb) => {
			if (shouldLog(hostname, config)) {
				const reqHeaders = (endCtx.clientToProxyRequest && endCtx.clientToProxyRequest.headers) || headers || {};
				const reqContentType = reqHeaders['content-type'] || reqHeaders['Content-Type'];
				const reqContentEncoding = reqHeaders['content-encoding'] || reqHeaders['Content-Encoding'];
				const resContentType = responseHeaders['content-type'] || responseHeaders['Content-Type'];
				const resContentEncoding = responseHeaders['content-encoding'] || responseHeaders['Content-Encoding'];

				let requestBodyTextForPii = '';
				let requestBodyTruncatedForPii = false;
				try {
					const meta = requestBody.getMeta();
					requestBodyTruncatedForPii = Boolean(meta && meta.truncated);
					const buf = requestBody.getBuffer();
					if (buf && buf.length > 0) requestBodyTextForPii = decodeTextBodyForPii(buf, reqContentType, reqContentEncoding);
				} catch {
					requestBodyTextForPii = '';
					requestBodyTruncatedForPii = false;
				}

				let responseBodyTextForPii = '';
				let responseBodyTruncatedForPii = false;
				try {
					const canUseTextBody =
						captureResponseBody &&
						captureBodiesForHost &&
						!(responseIsImage && captureResponseFiles && captureFilesForHost);
					if (canUseTextBody) {
						const meta = responseTextBody.getMeta();
						responseBodyTruncatedForPii = Boolean(meta && meta.truncated);
						const buf = responseTextBody.getBuffer();
						if (buf && buf.length > 0) responseBodyTextForPii = decodeTextBodyForPii(buf, resContentType, resContentEncoding);
					}
				} catch {
					responseBodyTextForPii = '';
					responseBodyTruncatedForPii = false;
				}

				const piiFields = buildEmailPiiFields({
					url: fullUrl,
					requestBodyText: requestBodyTextForPii,
					requestBodyTruncated: requestBodyTruncatedForPii,
					responseBodyText: responseBodyTextForPii,
					responseBodyTruncated: responseBodyTruncatedForPii,
					formFields: multipartCapture ? multipartCapture.state.fields : null,
				});

				let responseFileFields = {};
				if (responseIsImage && captureResponseFiles && captureFilesForHost) {
					const meta = responseFileBody.getMeta();
					if (!meta.truncated && meta.totalBytes > 0) {
						try {
							const { mime } = parseContentType(resContentType);
							const fileName = buildSavedFileName('res', mime);
							const absPath = path.join(path.resolve(process.cwd(), fileSaveDir), fileName);
							ensureDir(path.dirname(absPath));
							fs.writeFileSync(absPath, responseFileBody.getBuffer());
							responseFileFields = {
								responseContentType: String(resContentType || ''),
								responseContentEncoding: String(resContentEncoding || ''),
								responseBodyBytes: meta.totalBytes,
								responseBodyTruncated: false,
								responseBodyFileUrl: buildFileUrl(fileName),
								responseBodyFileBytes: meta.totalBytes,
							};
						} catch (e) {
							responseFileFields = {
								responseContentType: String(resContentType || ''),
								responseContentEncoding: String(resContentEncoding || ''),
								responseBodyBytes: meta.totalBytes,
								responseBodyTruncated: false,
								responseBodyFileSkipped: true,
								responseBodyFileSkipReason: 'write_error',
								responseBodyFileSkipError: e && e.message ? e.message : String(e),
								responseBodyFileMaxBytes: maxFileBytes,
							};
						}
					} else if (meta.truncated) {
						responseFileFields = {
							responseContentType: String(resContentType || ''),
							responseContentEncoding: String(resContentEncoding || ''),
							responseBodyBytes: meta.totalBytes,
							responseBodyTruncated: true,
							responseBodyFileSkipped: true,
							responseBodyFileSkipReason: 'too_large',
							responseBodyFileMaxBytes: maxFileBytes,
						};
					}
				}

				appendJsonl(
					logPath,
					Object.assign(
						buildLogEntry({ url: fullUrl, method, status: responseStatusCode, hostname }),
						{ isSSL: Boolean(endCtx.isSSL) },
						piiFields,
						multipartCapture
							? {
								requestMultipart: true,
								requestFormFields: multipartCapture.state.fields,
								requestUploadedFiles: multipartCapture.state.files,
								requestUploadedFilesSkipped: multipartCapture.state.skippedFiles,
								requestMultipartCompleted: multipartCapture.state.completed,
								requestMultipartErrors: multipartCapture.state.errors,
							}
							: {},
						captureRequestBody && captureBodiesForHost
							? requestBody.toLogFields('request', reqContentType, reqContentEncoding)
							: {},
						responseFileFields,
						captureResponseBody && captureBodiesForHost && !(responseIsImage && captureResponseFiles && captureFilesForHost)
							? responseTextBody.toLogFields('response', resContentType, resContentEncoding)
							: {}
					)
				);
			}
			cb();
		});

		callback();
	});

	proxy.listen({
		host: config.proxy.host,
		port: config.proxy.port,
	});

	console.log(`MITM proxy listening on ${config.proxy.host}:${config.proxy.port}`);
	console.log('First run may generate a local CA in the project directory; trust it for HTTPS interception.');
}

function main() {
	// エントリーポイント: 設定読み込み → ダッシュボード起動 → プロキシ起動
	const config = loadConfig();
	const blocking = config && config.blocking ? config.blocking : {};
	const defaultBlockDomains = Array.isArray(blocking.domains) ? blocking.domains : [];
	const policyPath = typeof blocking.dynamicPolicyPath === 'string' && blocking.dynamicPolicyPath ? blocking.dynamicPolicyPath : './data/policy.json';
	configurePolicyStore({ filePath: policyPath, defaultBlockDomains });
	startDashboard(config);
	startMitmProxy(config);
}

main();
