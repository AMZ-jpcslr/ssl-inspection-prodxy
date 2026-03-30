/*
ダッシュボード HTTP サーバ（Express）

このファイルがやること
- JSONLログ（`src/logStore.js`）から直近N件を読み込み、一覧/詳細ページを提供する
- `src/dashboard/render.js` のレンダラを呼び出してHTMLを返す
- 画像等の保存ファイル（inspection.fileSaveDir）を `/files` 配下で配信する
- （有効化されている場合）ログイン/ログアウトとセッションCookie検証で閲覧を保護する

どういう原理で動くか（要点）
- ダッシュボードは「ログの可視化」専用で、ログの生成はプロキシ本体（`src/main.js`）が行います。
- 一覧→詳細は “配列index” だけに依存するとログ増加でズレるため、
	エントリ内容から計算した安定キー（`_dashKey`）でも参照できるようにしています。
*/

const http = require('node:http');
const path = require('node:path');

const express = require('express');

const { readLastJsonlEntries } = require('../logStore');
const { appendAuditJsonl, readLastAuditEntries } = require('../auditStore');
const {
	configurePolicyStore,
	getBlockDomains,
	setBlockDomains,
	normalizeDomainList,
} = require('../policyStore');
const { parseCookies, signDashboardSession, verifyDashboardSession, verifyScryptPassword } = require('./auth');
const {
	escapeHtml,
	truncateForDashboard,
	DASHBOARD_BODY_PAGE_MAX_CHARS,
	renderDashboardHtml,
	renderPiiDetailHtml,
	computeDashboardEntryKey,
} = require('./render');

function startDashboard(config) {
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

	function getRemoteAddr(req) {
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

	function requireAuth(req, res, next) {
		if (!authEnabled) return next();
		if (!sessionSecret || !authPasswordHash) {
			res.statusCode = 500;
			res.setHeader('content-type', 'text/plain; charset=utf-8');
			res.end('Dashboard auth is enabled but not configured (missing sessionSecret/passwordHash).');
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

	if (authEnabled) {
		app.get('/login', (req, res) => {
			res.setHeader('cache-control', 'no-store');
			res.setHeader('content-type', 'text/html; charset=utf-8');
			res.end(loginPageHtml(''));
		});

		app.post('/login', (req, res) => {
			res.setHeader('cache-control', 'no-store');
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
			res.setHeader('set-cookie', `${cookieName}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`);
			res.statusCode = 302;
			res.setHeader('location', '/');
			res.end();
		});

		app.get('/logout', (req, res) => {
			audit('logout', req, {});
			res.setHeader('set-cookie', `${cookieName}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`);
			res.statusCode = 302;
			res.setHeader('location', '/login');
			res.end();
		});

		app.use((req, res, next) => {
			if (req.path === '/login' || req.path === '/logout') return next();
			return requireAuth(req, res, next);
		});
	}

	app.use('/files', express.static(filesAbs, { fallthrough: true, index: false }));

	function findEntryByDashboardIdParam(entries, idParam) {
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

	app.get('/', (req, res) => {
		const entries = readLastJsonlEntries(logPath, maxEntries);
		entries.reverse();
		const forRender = entries.map((e, i) => ({ ...e, _dashId: i, _dashKey: computeDashboardEntryKey(e) }));
		res.setHeader('content-type', 'text/html; charset=utf-8');
		const message = req.query && typeof req.query.msg === 'string' ? req.query.msg : '';
		res.end(
			renderDashboardHtml(forRender, {
				authEnabled,
				blockDomains: getBlockDomains(),
				message,
			})
		);
	});

	app.post('/settings/blocking', (req, res) => {
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

	app.get('/audit', (req, res) => {
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

		let body = '';
		if (text) body = text;
		else if (base64) body = base64;
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
