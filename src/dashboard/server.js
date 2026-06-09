/*
メモ
ダッシュボード HTTP サーバ（Express）

このファイルがやること
- JSONLログ（`src/logStore.js`）から直近N件を読み込み、一覧/詳細ページを提供する
- `src/dashboard/render.js` のレンダラを呼び出してHTMLを返す
- 画像等の保存ファイル（inspection.fileSaveDir）を `/files` 配下で配信する
- （有効化されている場合）ログイン/ログアウトとセッションCookie検証で閲覧を保護する

原理（要点）
- ダッシュボードは「ログの可視化」専用で、ログの生成はプロキシ本体（`src/main.js`）が行う。
- 一覧→詳細は “配列index” だけに依存するとログ増加でズレるため、
	エントリ内容から計算した安定キー（`_dashKey`）でも参照できるようにしている。
*/

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const express = require('express');

const { clearJsonl, readLastJsonlEntries } = require('../logStore');
const { appendAuditJsonl, readLastAuditEntries } = require('../auditStore');
const {
	configurePolicyStore,
	getBlockDomains,
	setBlockDomains,
	normalizeDomainList,
} = require('../policyStore');
const { addTemporaryAllow } = require('../phishingStore');
const {
	createScryptPasswordHash,
	generateSessionSecret,
	parseCookies,
	signDashboardSession,
	verifyDashboardSession,
	verifyScryptPassword,
} = require('./auth');
const {
	escapeHtml,
	truncateForDashboard,
	DASHBOARD_BODY_PAGE_MAX_CHARS,
	renderDashboardHtml,
	renderPiiDetailHtml,
	computeDashboardEntryKey,
} = require('./render');

function startDashboard(config) {
	// ダッシュボードは「ログを読む/見せる」だけのサーバ。
	// - ログの生成はプロキシ本体（src/main.js）が行い、ここはそれを読む。
	// - 認証が有効なら、ログイン→署名付きCookie→以後検証、で閲覧を保護する。
	// ログを読み込んで一覧表示するだけの最小UI
	const app = express();
	app.disable('x-powered-by');
	app.use(express.urlencoded({ extended: false, limit: '10kb' }));
	const logPath = config.logging.path;
	const maxEntries = config.logging.maxEntriesInMemory || 500;
	const auditPath =
		config && config.auditLogging && typeof config.auditLogging.path === 'string' && config.auditLogging.path
			? config.auditLogging.path
			: './data/audit.log.jsonl';
	const maxAuditEntries =
		config && config.auditLogging && Number.isFinite(config.auditLogging.maxEntriesInMemory)
			? config.auditLogging.maxEntriesInMemory
			: 200;
	const inspection = config && config.inspection ? config.inspection : {};
	const fileSaveDir = typeof inspection.fileSaveDir === 'string' && inspection.fileSaveDir ? inspection.fileSaveDir : './data/files';
	const filesAbs = path.resolve(process.cwd(), fileSaveDir);

	const blocking = config && config.blocking ? config.blocking : {};
	const defaultBlockDomains = Array.isArray(blocking.domains) ? blocking.domains : [];
	const policyPath = typeof blocking.dynamicPolicyPath === 'string' && blocking.dynamicPolicyPath ? blocking.dynamicPolicyPath : './data/policy.json';
	configurePolicyStore({ filePath: policyPath, defaultBlockDomains });

	const dashboardAuth = config && config.dashboardAuth ? config.dashboardAuth : {};
	const authEnabled = dashboardAuth && dashboardAuth.enabled === true;
	const authUsername = typeof dashboardAuth.username === 'string' && dashboardAuth.username ? dashboardAuth.username : 'admin';
	const authPasswordHash = dashboardAuth.passwordHash;
	const sessionSecret = typeof dashboardAuth.sessionSecret === 'string' ? dashboardAuth.sessionSecret : '';
	const sessionTtlSeconds = Number.isFinite(dashboardAuth.sessionTtlSeconds) ? dashboardAuth.sessionTtlSeconds : 60 * 60 * 8;
	const cookieName = 'dashboard_session';
	const setupRequired = authEnabled && !isDashboardAuthConfigured();

	function isDashboardAuthConfigured() {
		return Boolean(
			dashboardAuth &&
				dashboardAuth.passwordHash &&
				dashboardAuth.passwordHash.saltBase64 &&
				dashboardAuth.passwordHash.hashBase64 &&
				sessionSecret
		);
	}

	function csrfTokenForUser(username) {
		if (!authEnabled || !sessionSecret || !username) return '';
		return signDashboardSession(`csrf:${username}`, 4102444800, sessionSecret);
	}

	function verifyCsrf(req) {
		if (!authEnabled) return true;
		const username = getAuthedUsername(req);
		if (!username) return false;
		const token = req.body && typeof req.body.csrfToken === 'string' ? req.body.csrfToken : '';
		return token && token === csrfTokenForUser(username);
	}

	function requireCsrf(req, res, next) {
		if (verifyCsrf(req)) return next();
		res.statusCode = 403;
		res.setHeader('content-type', 'text/plain; charset=utf-8');
		res.end('Invalid CSRF token');
	}

	function canWriteFilePath(filePath) {
		try {
			const abs = path.resolve(process.cwd(), filePath);
			fs.mkdirSync(path.dirname(abs), { recursive: true });
			fs.accessSync(path.dirname(abs), fs.constants.W_OK);
			return true;
		} catch {
			return false;
		}
	}

	function canWriteDir(dirPath) {
		try {
			const abs = path.resolve(process.cwd(), dirPath);
			fs.mkdirSync(abs, { recursive: true });
			fs.accessSync(abs, fs.constants.W_OK);
			return true;
		} catch {
			return false;
		}
	}

	function buildHealthStatus() {
		const caPath = path.resolve(process.cwd(), '.http-mitm-proxy/certs/ca.pem');
		const bodyDomains = inspection && Array.isArray(inspection.bodyCaptureDomains) ? inspection.bodyCaptureDomains : [];
		const fileDomains = inspection && Array.isArray(inspection.fileCaptureDomains) ? inspection.fileCaptureDomains : [];
		return [
			{
				label: 'Dashboard auth',
				ok: !authEnabled || isDashboardAuthConfigured(),
				detail: authEnabled ? (isDashboardAuthConfigured() ? 'configured' : 'setup required') : 'disabled',
			},
			{
				label: 'Local CA',
				ok: fs.existsSync(caPath),
				detail: fs.existsSync(caPath) ? '.http-mitm-proxy/certs/ca.pem' : 'created after first HTTPS use',
			},
			{
				label: 'Access log',
				ok: canWriteFilePath(logPath),
				detail: logPath,
			},
			{
				label: 'Saved files',
				ok: canWriteDir(fileSaveDir),
				detail: fileSaveDir,
			},
			{
				label: 'Body capture scope',
				ok: bodyDomains.length > 0,
				detail: bodyDomains.length > 0 ? bodyDomains.join(', ') : 'all domains',
			},
			{
				label: 'File capture scope',
				ok: fileDomains.length > 0,
				detail: fileDomains.length > 0 ? fileDomains.join(', ') : 'all domains',
			},
		];
	}

	function getRemoteAddr(req) {
		// 監査ログ用に、リクエスト元アドレスを可能な範囲で取る。
		// - x-forwarded-for はプロキシ/ロードバランサ配下のときに入ることがある。
		try {
			const xf = req && req.headers ? req.headers['x-forwarded-for'] : '';
			if (typeof xf === 'string' && xf) return xf.split(',')[0].trim();
		} catch {
			// ignore
		}
		try {
			return req && req.socket ? String(req.socket.remoteAddress || '') : '';
		} catch {
			return '';
		}
	}

	function getAuthedUsername(req) {
		// 「現在ログイン済みか？」を Cookie から判定し、OKならユーザー名を返す。
		// - authEnabledがfalseなら常に空文字（＝未認証扱い）。
		if (!authEnabled) return '';
		if (!sessionSecret || !authPasswordHash) return '';
		try {
			const cookies = parseCookies(req.headers.cookie);
			const token = cookies[cookieName];
			if (!token) return '';
			const parts = token.split('.');
			if (parts.length !== 4 || parts[0] !== 'v1') return '';
			const u = parts[1];
			const exp = Number(parts[2]);
			const sig = parts[3];
			if (u === authUsername && verifyDashboardSession(u, exp, sig, sessionSecret)) return u;
			return '';
		} catch {
			return '';
		}
	}

	function audit(action, req, extra, actorOverride) {
		// 監査ログは「管理者操作の履歴」。
		// - login/logout/設定変更など、ダッシュボード側の重要イベントをJSONLに追記する。
		try {
			appendAuditJsonl(path.resolve(process.cwd(), auditPath), {
				timestamp: new Date().toISOString(),
				action,
				actor: actorOverride || getAuthedUsername(req) || 'unauthenticated',
				remoteAddr: getRemoteAddr(req),
				extra: extra && typeof extra === 'object' ? extra : undefined,
			});
		} catch {
			// ignore
		}
	}

	function loginPageHtml(message) {
		// ログインページはテンプレートなしでHTML文字列を組み立てる（MVP）。
		const msg = message ? `<div style="color:#a00; margin:0 0 12px 0;">${escapeHtml(message)}</div>` : '';
		return `<!doctype html>
<html lang="ja">
	<head>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<title>Dashboard Login</title>
		<style>
			body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }
			.card { max-width: 420px; border: 1px solid #ddd; border-radius: 8px; padding: 16px; }
			label { display: block; margin-top: 10px; }
			input { width: 100%; padding: 8px; box-sizing: border-box; }
			button { margin-top: 14px; padding: 10px 12px; }
		</style>
	</head>
	<body>
		<div class="card">
			<h1 style="font-size:18px; margin: 0 0 10px 0;">Dashboard Login</h1>
			${msg}
			<form method="post" action="/login">
				<label>username</label>
				<input name="username" autocomplete="username" />
				<label>password</label>
				<input name="password" type="password" autocomplete="current-password" />
				<button type="submit">login</button>
			</form>
		</div>
	</body>
</html>`;
	}

	function setupPageHtml(message) {
		const msg = message ? `<div style="color:#a00; margin:0 0 12px 0;">${escapeHtml(message)}</div>` : '';
		return `<!doctype html>
<html lang="ja">
	<head>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<title>Initial Setup</title>
		<style>
			body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }
			.card { max-width: 520px; border: 1px solid #ddd; border-radius: 8px; padding: 16px; }
			label { display: block; margin-top: 10px; }
			input { width: 100%; padding: 8px; box-sizing: border-box; }
			button { margin-top: 14px; padding: 10px 12px; }
			.meta { color:#444; line-height: 1.5; }
		</style>
	</head>
	<body>
		<div class="card">
			<h1 style="font-size:18px; margin: 0 0 10px 0;">Initial Dashboard Setup</h1>
			<p class="meta">管理画面のパスワードを作成します。秘密情報は Git 管理外の <code>config.local.json</code> に保存されます。</p>
			${msg}
			<form method="post" action="/setup">
				<label>username</label>
				<input name="username" value="${escapeHtml(authUsername)}" autocomplete="username" />
				<label>password</label>
				<input name="password" type="password" autocomplete="new-password" />
				<label>confirm password</label>
				<input name="passwordConfirm" type="password" autocomplete="new-password" />
				<button type="submit">create admin account</button>
			</form>
		</div>
	</body>
</html>`;
	}

	function writeLocalDashboardAuth(username, password) {
		const localConfigPath = path.resolve(process.cwd(), 'config.local.json');
		let localConfig = {};
		try {
			if (fs.existsSync(localConfigPath) && fs.statSync(localConfigPath).isFile()) {
				localConfig = JSON.parse(fs.readFileSync(localConfigPath, 'utf8'));
			}
		} catch {
			localConfig = {};
		}
		localConfig.dashboardAuth = {
			...(localConfig.dashboardAuth && typeof localConfig.dashboardAuth === 'object' ? localConfig.dashboardAuth : {}),
			enabled: true,
			username,
			passwordHash: createScryptPasswordHash(password),
			sessionSecret: generateSessionSecret(),
			sessionTtlSeconds,
		};
		fs.writeFileSync(localConfigPath, `${JSON.stringify(localConfig, null, 2)}\n`, 'utf8');
	}

	function requireAuth(req, res, next) {
		// 「認証必須」ガード。
		// - Cookieが無い/壊れている/期限切れ/署名NG なら /login にリダイレクトする。
		if (!authEnabled) return next();
		if (setupRequired) {
			res.statusCode = 302;
			res.setHeader('location', '/setup');
			res.end();
			return;
		}
		const cookies = parseCookies(req.headers.cookie);
		const token = cookies[cookieName];
		if (token) {
			const parts = token.split('.');
			if (parts.length === 4 && parts[0] === 'v1') {
				const u = parts[1];
				const exp = Number(parts[2]);
				const sig = parts[3];
				if (u === authUsername && verifyDashboardSession(u, exp, sig, sessionSecret)) {
					return next();
				}
			}
		}
		res.statusCode = 302;
		res.setHeader('location', '/login');
		res.end();
	}

	app.get('/phishing/proceed', (req, res) => {
		const rawUrl = req.query && typeof req.query.url === 'string' ? req.query.url : '';
		let target;
		try {
			target = new URL(rawUrl);
			if (target.protocol !== 'http:' && target.protocol !== 'https:') throw new Error('unsupported protocol');
		} catch {
			res.statusCode = 400;
			res.setHeader('content-type', 'text/plain; charset=utf-8');
			res.end('Bad phishing proceed URL');
			return;
		}

		addTemporaryAllow(target.toString(), 5 * 60);
		audit('phishing_warning_proceed', req, { host: target.hostname, url: target.toString() });
		res.statusCode = 302;
		res.setHeader('location', target.toString());
		res.end();
	});

	if (authEnabled) {
		app.get('/setup', (req, res) => {
			res.setHeader('cache-control', 'no-store');
			res.setHeader('content-type', 'text/html; charset=utf-8');
			if (!setupRequired) {
				res.statusCode = 302;
				res.setHeader('location', '/login');
				res.end();
				return;
			}
			res.end(setupPageHtml(''));
		});

		app.post('/setup', (req, res) => {
			res.setHeader('cache-control', 'no-store');
			if (!setupRequired) {
				res.statusCode = 302;
				res.setHeader('location', '/login');
				res.end();
				return;
			}
			const username = req.body && typeof req.body.username === 'string' && req.body.username.trim()
				? req.body.username.trim()
				: 'admin';
			const password = req.body && typeof req.body.password === 'string' ? req.body.password : '';
			const passwordConfirm = req.body && typeof req.body.passwordConfirm === 'string' ? req.body.passwordConfirm : '';
			if (password.length < 8) {
				res.statusCode = 400;
				res.setHeader('content-type', 'text/html; charset=utf-8');
				res.end(setupPageHtml('Password must be at least 8 characters.'));
				return;
			}
			if (password !== passwordConfirm) {
				res.statusCode = 400;
				res.setHeader('content-type', 'text/html; charset=utf-8');
				res.end(setupPageHtml('Passwords do not match.'));
				return;
			}
			try {
				writeLocalDashboardAuth(username, password);
				audit('initial_setup', req, { username }, username);
				res.statusCode = 200;
				res.setHeader('content-type', 'text/html; charset=utf-8');
				res.end(`<!doctype html>
<html lang="ja">
	<head>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<title>Setup Complete</title>
		<style>
			body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }
			.card { max-width: 520px; border: 1px solid #ddd; border-radius: 8px; padding: 16px; }
			code { background:#f5f5f5; padding:2px 6px; border-radius:4px; }
		</style>
	</head>
	<body>
		<div class="card">
			<h1 style="font-size:18px; margin: 0 0 10px 0;">Setup complete</h1>
			<p><code>config.local.json</code> を作成しました。</p>
			<p>一度プロキシを再起動してから、<a href="/login">ログイン画面</a>を開いてください。</p>
		</div>
	</body>
</html>`);
			} catch (e) {
				res.statusCode = 500;
				res.setHeader('content-type', 'text/html; charset=utf-8');
				res.end(setupPageHtml(`Failed to write config.local.json: ${e && e.message ? e.message : String(e)}`));
			}
		});

		app.get('/login', (req, res) => {
			res.setHeader('cache-control', 'no-store');
			res.setHeader('content-type', 'text/html; charset=utf-8');
			if (setupRequired) {
				res.statusCode = 302;
				res.setHeader('location', '/setup');
				res.end();
				return;
			}
			const message = req.query && req.query.setup === 'complete' ? 'Setup complete. Please log in.' : '';
			res.end(loginPageHtml(message));
		});

		app.post('/login', (req, res) => {
			res.setHeader('cache-control', 'no-store');
			if (setupRequired) {
				res.statusCode = 302;
				res.setHeader('location', '/setup');
				res.end();
				return;
			}
			const username = req.body && typeof req.body.username === 'string' ? req.body.username : '';
			const password = req.body && typeof req.body.password === 'string' ? req.body.password : '';
			if (username !== authUsername || !verifyScryptPassword(password, authPasswordHash)) {
				res.statusCode = 401;
				res.setHeader('content-type', 'text/html; charset=utf-8');
				res.end(loginPageHtml('Invalid username or password'));
				return;
			}
			audit('login', req, { username: authUsername }, authUsername);
			const maxAge = Math.max(60, sessionTtlSeconds);
			const exp = Math.floor(Date.now() / 1000) + maxAge;
			const sig = signDashboardSession(authUsername, exp, sessionSecret);
			const token = `v1.${authUsername}.${exp}.${sig}`;
			// Cookieの属性（なぜ必要？）
			// - HttpOnly: JSから読めないようにしてXSS時の漏えいリスクを下げる
			// - SameSite=Lax: 外部サイトからの“勝手な送信”（CSRFっぽい動き）を緩和
			// - Path=/: ダッシュボード配下で有効にする
			// - Max-Age: 期限（サーバ側のexpとも整合）
			// 注意: HTTPS前提なら Secure も付けたいが、ローカルMVP用途なので付けていない
			res.setHeader('set-cookie', `${cookieName}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`);
			res.statusCode = 302;
			res.setHeader('location', '/');
			res.end();
		});

		// logoutは「Cookieを消す」だけのシンプルな実装。
		// - クライアントに古いCookieを上書きで消してもらう（Max-Age=0）。
		// - 期限切れ/署名NGのCookieは requireAuth で弾かれるので、ここでは「正しいCookieが来たときだけ監査ログに残す」ようにしている。
		app.get('/logout', (req, res) => {
			audit('logout', req, {});
			res.setHeader('set-cookie', `${cookieName}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`);
			res.statusCode = 302;
			res.setHeader('location', '/login');
			res.end();
		});

		app.use((req, res, next) => {
			if (req.path === '/setup' || req.path === '/login' || req.path === '/logout') return next();
			return requireAuth(req, res, next);
		});
	}

	// 保存済みファイル（アップロード画像/レスポンス画像）を配信する。
	// - src/main.js が inspection.fileSaveDir 配下に保存したファイルを、リンクで見られるようにする。
	// - index: false でディレクトリ一覧は出さない（MVPでも“うっかり露出”を減らす）。
	app.use('/files', express.static(filesAbs, { fallthrough: true, index: false }));

	function findEntryByDashboardIdParam(entries, idParam) {
		// URLの :id を解釈してログエントリを探す。
		// - 数字だけなら index として扱う（互換）
		// - それ以外は computeDashboardEntryKey で作った安定キーとして扱う
		// なぜ2方式？
		// - 以前の実装が index 指定だけだと、ログが増えた時に参照がズレる（一覧のN番目が別物になる）。
		// - 安定キー方式なら「その通信の特徴から作った短いhash」で引けるのでズレにくい。
		const s = String(idParam || '');
		if (/^\d+$/.test(s)) {
			const idx = Number(s);
			return { entry: entries[idx], index: idx };
		}
		if (!s) return { entry: undefined, index: -1 };
		for (let i = 0; i < entries.length; i++) {
			if (computeDashboardEntryKey(entries[i]) === s) return { entry: entries[i], index: i };
		}
		return { entry: undefined, index: -1 };
	}

	function firstQueryValue(value) {
		if (Array.isArray(value)) return value.length > 0 ? String(value[0] || '') : '';
		return value === undefined || value === null ? '' : String(value);
	}

	function parseLogFilters(query) {
		const q = firstQueryValue(query && query.q).trim();
		const domain = firstQueryValue(query && query.domain).trim().toLowerCase();
		const method = firstQueryValue(query && query.method).trim().toUpperCase();
		const status = firstQueryValue(query && query.status).trim();
		return {
			q,
			domain,
			method,
			status,
			onlyPii: firstQueryValue(query && query.pii) === '1',
			onlyBlocked: firstQueryValue(query && query.blocked) === '1',
			onlyFiles: firstQueryValue(query && query.files) === '1',
		};
	}

	function entryHasFile(entry) {
		if (!entry) return false;
		if (typeof entry.requestBodyFileUrl === 'string' && entry.requestBodyFileUrl) return true;
		if (typeof entry.responseBodyFileUrl === 'string' && entry.responseBodyFileUrl) return true;
		if (Array.isArray(entry.requestUploadedFiles) && entry.requestUploadedFiles.length > 0) return true;
		return false;
	}

	function entryMatchesFilters(entry, filters) {
		if (!entry) return false;
		const f = filters && typeof filters === 'object' ? filters : {};
		const domain = String(entry.domain || '').toLowerCase();
		const url = String(entry.URL || '').toLowerCase();
		const method = String(entry.method || '').toUpperCase();
		const status = String(entry.status === undefined || entry.status === null ? '' : entry.status);
		const pii = entry.piiEmailDetected === true || entry.piiCardDetected === true || entry.piiPhoneDetected === true;

		if (f.q) {
			const needle = String(f.q).toLowerCase();
			const haystack = [
				entry.timestamp,
				entry.domain,
				entry.URL,
				entry.method,
				entry.status,
				entry.requestContentType,
				entry.responseContentType,
			]
				.map((v) => String(v === undefined || v === null ? '' : v).toLowerCase())
				.join('\n');
			if (!haystack.includes(needle)) return false;
		}
		if (f.domain && !domain.includes(f.domain) && !url.includes(f.domain)) return false;
		if (f.method && method !== f.method) return false;
		if (f.status && !status.startsWith(f.status)) return false;
		if (f.onlyPii && !pii) return false;
		if (f.onlyBlocked && entry.blocked !== true) return false;
		if (f.onlyFiles && !entryHasFile(entry)) return false;
		return true;
	}

	app.get('/', (req, res) => {
		// 一覧ページ。
		// - JSONLを末尾N件だけ読み、表示しやすいように並び順を整える。
		// - ここでは「最新が上」にしたいので reverse() している。
		const entries = readLastJsonlEntries(logPath, maxEntries);
		entries.reverse();
		const allForRender = entries.map((e, i) => ({ ...e, _dashId: i, _dashKey: computeDashboardEntryKey(e) }));
		const filters = parseLogFilters(req.query || {});
		const forRender = allForRender.filter((entry) => entryMatchesFilters(entry, filters));
		res.setHeader('content-type', 'text/html; charset=utf-8');
		const message = req.query && typeof req.query.msg === 'string' ? req.query.msg : '';
		res.end(
			renderDashboardHtml(forRender, {
				authEnabled,
				blockDomains: getBlockDomains(),
				filters,
				totalEntries: allForRender.length,
				csrfToken: csrfTokenForUser(getAuthedUsername(req)),
				healthStatus: buildHealthStatus(),
				message,
			})
		);
	});

	app.post('/settings/blocking', requireCsrf, (req, res) => {
		// ブロック対象ドメインの更新。
		// - textarea に1行1ドメインで入力された値を正規化し、policyStoreへ保存する。
		// - 保存直後からプロキシ側の isBlocked() 判定にも反映される（メモリキャッシュ参照のため）。
		const raw = req.body && typeof req.body.blockDomains === 'string' ? req.body.blockDomains : '';
		const next = normalizeDomainList(
			raw
				.split(/\r?\n/)
				.map((s) => String(s || '').trim())
				.filter(Boolean)
		);
		const prev = getBlockDomains();
		const updated = setBlockDomains(next);

		const prevSet = new Set(prev);
		const updatedSet = new Set(updated);
		const added = updated.filter((d) => !prevSet.has(d));
		const removed = prev.filter((d) => !updatedSet.has(d));
		audit('update_block_domains', req, { added, removed, count: updated.length });

		res.statusCode = 302;
		res.setHeader('location', '/?msg=blocklist%20updated');
		res.end();
	});

	app.post('/settings/logs/clear', requireCsrf, (req, res) => {
		try {
			clearJsonl(logPath);
			audit('clear_access_log', req, { path: logPath });
			res.statusCode = 302;
			res.setHeader('location', '/?msg=access%20log%20cleared');
			res.end();
		} catch (e) {
			res.statusCode = 500;
			res.setHeader('content-type', 'text/plain; charset=utf-8');
			res.end(`Failed to clear access log: ${e && e.message ? e.message : String(e)}`);
		}
	});

	app.get('/audit', (req, res) => {
		// 監査ログの一覧（誰がいつ何をしたか）。
		// - UI目的なので末尾N件だけ読む。
		// - cache-control: no-store でブラウザキャッシュに残りにくくする（監査ログは機微になりうる）。
		const entries = readLastAuditEntries(path.resolve(process.cwd(), auditPath), maxAuditEntries);
		entries.reverse();
		const rows = entries
			.map((e) => {
				const ts = escapeHtml(String((e && e.timestamp) || ''));
				const actor = escapeHtml(String((e && e.actor) || ''));
				const action = escapeHtml(String((e && e.action) || ''));
				const addr = escapeHtml(String((e && e.remoteAddr) || ''));
				let extra = '';
				try {
					extra = e && e.extra ? JSON.stringify(e.extra) : '';
				} catch {
					extra = '';
				}
				const extraHtml = extra ? `<pre style="white-space:pre-wrap; word-break:break-word; margin:0">${escapeHtml(extra)}</pre>` : '';
				return `<tr>
					<td>${ts}</td>
					<td>${actor}</td>
					<td>${action}</td>
					<td>${addr}</td>
					<td>${extraHtml}</td>
				</tr>`;
			})
			.join('');

		res.statusCode = 200;
		res.setHeader('cache-control', 'no-store');
		res.setHeader('content-type', 'text/html; charset=utf-8');
		res.end(`<!doctype html>
<html lang="ja">
	<head>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<title>Audit Log</title>
		<style>
			body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 16px; }
			table { width: 100%; border-collapse: collapse; }
			th, td { border-bottom: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
			th { position: sticky; top: 0; background: #fff; }
			.meta { margin: 0 0 12px 0; color: #444; }
		</style>
	</head>
	<body>
		<div class="meta"><a href="/">&larr; back</a></div>
		<p class="meta">最新 ${entries.length} 件（更新はリロード）</p>
		<table>
			<thead>
				<tr>
					<th>timestamp</th>
					<th>actor</th>
					<th>action</th>
					<th>remote</th>
					<th>extra</th>
				</tr>
			</thead>
			<tbody>
				${rows}
			</tbody>
		</table>
	</body>
</html>`);
	});

	app.get('/entry/:id/body', (req, res) => {
		// 本文詳細表示ページ。
		// - 一覧には本文を埋め込まず、別ページで見せる（重い・危険な文字列を扱うため）。
		// - prefix で request/response のどちらを見るかを選ぶ。
		const idParam = req.params.id;
		const prefix =
			req.query && req.query.prefix === 'request'
				? 'request'
				: req.query && req.query.prefix === 'response'
					? 'response'
					: '';
		if (!prefix) {
			res.statusCode = 400;
			res.setHeader('content-type', 'text/plain; charset=utf-8');
			res.end('Bad request');
			return;
		}

		// JSONLから読み込んだ entries は「古い→新しい」の順で返ってくるので、最新が上になるよう reverse。
		const entries = readLastJsonlEntries(logPath, maxEntries);
		entries.reverse();
		const { entry } = findEntryByDashboardIdParam(entries, idParam);
		if (!entry) {
			res.statusCode = 404;
			res.setHeader('content-type', 'text/plain; charset=utf-8');
			res.end('Not found');
			return;
		}

		const bytes = entry && typeof entry[`${prefix}BodyBytes`] === 'number' ? entry[`${prefix}BodyBytes`] : 0;
		const truncated = Boolean(entry && entry[`${prefix}BodyTruncated`]);
		const contentType = escapeHtml((entry && entry[`${prefix}ContentType`]) || '');
		const contentEncoding = escapeHtml((entry && entry[`${prefix}ContentEncoding`]) || '');
		const charset = escapeHtml((entry && entry[`${prefix}Charset`]) || '');
		const fileUrl = entry && typeof entry[`${prefix}BodyFileUrl`] === 'string' ? entry[`${prefix}BodyFileUrl`] : '';
		const text = entry && typeof entry[`${prefix}BodyText`] === 'string' ? entry[`${prefix}BodyText`] : '';
		const base64 = entry && typeof entry[`${prefix}BodyBase64`] === 'string' ? entry[`${prefix}BodyBase64`] : '';
		const kind = text ? 'text' : base64 ? 'base64' : 'none';
		const meta = [contentType, charset ? `charset=${charset}` : '', contentEncoding ? `enc=${contentEncoding}` : '']
			.filter(Boolean)
			.join(' ');

		// ログには「テキストとして保存」か「base64として保存」かのどちらかが入る。
		// - どちらも無い場合は none。
		let body = '';
		if (text) body = text;
		else if (base64) body = base64;
		// 表示を重くしないため、ここで“表示用の上限”を適用（ログ自体は別ファイルに残っている想定）。
		const bodyLimited = truncateForDashboard(body, DASHBOARD_BODY_PAGE_MAX_CHARS);

		res.statusCode = 200;
		res.setHeader('content-type', 'text/html; charset=utf-8');
		res.end(`<!doctype html>
<html lang="ja">
	<head>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<title>Body view</title>
		<style>
			body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 16px; }
			pre { white-space: pre-wrap; word-break: break-word; }
			.meta { color: #444; margin-bottom: 12px; }
		</style>
	</head>
	<body>
		<div class="meta"><a href="/">&larr; back</a></div>
		<div class="meta">${escapeHtml(prefix)} body: ${escapeHtml(String(bytes))}B${truncated ? '…' : ''} ${escapeHtml(
			kind
		)}${meta ? ` (${escapeHtml(meta)})` : ''}</div>
		${fileUrl ? `<div class="meta">file: <a href="${escapeHtml(fileUrl)}" target="_blank" rel="noopener noreferrer">download</a></div>` : ''}
		<pre>${escapeHtml(bodyLimited || '')}</pre>
	</body>
</html>`);
	});

	app.get('/entry/:id/pii', (req, res) => {
		// PII（メール）詳細ページ。
		// - wantReveal=1 のとき raw 候補も見せられるが、render側で authEnabled を見て制御する。
		const idParam = req.params.id;

		const entries = readLastJsonlEntries(logPath, maxEntries);
		entries.reverse();
		const { entry, index } = findEntryByDashboardIdParam(entries, idParam);
		if (!entry) {
			res.statusCode = 404;
			res.setHeader('content-type', 'text/plain; charset=utf-8');
			res.end('Not found');
			return;
		}

		// revealはクエリパラメータ。true/1 を許容する（手入力でも分かりやすく）。
		const wantReveal = req.query && (req.query.reveal === '1' || req.query.reveal === 'true');

		res.statusCode = 200;
		res.setHeader('cache-control', 'no-store');
		res.setHeader('content-type', 'text/html; charset=utf-8');
		res.end(renderPiiDetailHtml({ entry, idParam, index, authEnabled, wantReveal }));
	});

	const server = http.createServer(app);
	server.on('error', (err) => {
		console.error(
			`Dashboard failed to start on http://${config.dashboard.host}:${config.dashboard.port}:`,
			err && err.message ? err.message : err
		);
		process.exitCode = 1;
	});
	server.listen(config.dashboard.port, config.dashboard.host, () => {
		console.log(`Dashboard listening on http://${config.dashboard.host}:${config.dashboard.port}`);
	});
}

module.exports = { startDashboard };
