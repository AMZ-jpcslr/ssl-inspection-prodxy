/*
メモ
ダッシュボード認証

このファイルの担当
- Cookie をパースする
- 署名付きセッションCookie（HMAC-SHA256）を生成/検証する
- scrypt パスワードハッシュを検証する

要点
- 認証が有効な場合、ログインで発行するCookieは「ユーザー名 + 有効期限」を含み、
	それに対してサーバ側秘密（sessionSecret）でHMAC署名を付ける。
- 受信時は署名を timingSafeEqual で比較し、改ざん検出を行う。
- パスワードは平文保存せず、scrypt の派生鍵とソルト/パラメータを config から受け取って照合。
*/

const crypto = require('node:crypto');

function base64UrlEncode(buf) {
	return Buffer.from(buf)
		.toString('base64')
		.replaceAll('+', '-')
		.replaceAll('/', '_')
		.replaceAll('=', '');
}

function base64UrlDecode(s) {
	const str = String(s || '').replaceAll('-', '+').replaceAll('_', '/');
	const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
	return Buffer.from(str + pad, 'base64');
}

function parseCookies(cookieHeader) {
	const out = {};
	const raw = String(cookieHeader || '');
	if (!raw) return out;
	for (const part of raw.split(';')) {
		const idx = part.indexOf('=');
		if (idx <= 0) continue;
		const k = part.slice(0, idx).trim();
		const v = part.slice(idx + 1).trim();
		if (!k) continue;
		out[k] = v;
	}
	return out;
}

function signDashboardSession(username, expEpochSeconds, sessionSecret) {
	const payload = `${username}.${expEpochSeconds}`;
	const mac = crypto.createHmac('sha256', String(sessionSecret)).update(payload).digest();
	return base64UrlEncode(mac);
}

function verifyDashboardSession(username, expEpochSeconds, sig, sessionSecret) {
	if (!username || !Number.isFinite(expEpochSeconds) || !sig || !sessionSecret) return false;
	const now = Math.floor(Date.now() / 1000);
	if (expEpochSeconds <= now) return false;
	const expected = signDashboardSession(username, expEpochSeconds, sessionSecret);
	try {
		const a = base64UrlDecode(expected);
		const b = base64UrlDecode(sig);
		return a.length === b.length && crypto.timingSafeEqual(a, b);
	} catch {
		return false;
	}
}

function verifyScryptPassword(password, passwordHash) {
	if (!passwordHash || typeof passwordHash !== 'object') return false;
	if (passwordHash.algorithm !== 'scrypt') return false;
	const params = passwordHash.params && typeof passwordHash.params === 'object' ? passwordHash.params : {};
	const N = Number(params.N);
	const r = Number(params.r);
	const p = Number(params.p);
	const keyLen = Number(params.keyLen);
	if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p) || !Number.isFinite(keyLen)) return false;
	if (!passwordHash.saltBase64 || !passwordHash.hashBase64) return false;

	const salt = Buffer.from(String(passwordHash.saltBase64), 'base64');
	const expected = Buffer.from(String(passwordHash.hashBase64), 'base64');
	const derived = crypto.scryptSync(String(password), salt, keyLen, {
		N,
		r,
		p,
		maxmem: 64 * 1024 * 1024,
	});
	return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
}

module.exports = {
	parseCookies,
	signDashboardSession,
	verifyDashboardSession,
	verifyScryptPassword,
};
