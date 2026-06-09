/*
メモ
フィッシング警告の一時許可ストア

目的
- 怪しいURLを一度警告ページで止めたあと、ユーザーが「続行」を選んだURLだけ短時間許可する。
- DBなしのMVPとして、プロセス内メモリに TTL 付きで保持する。
*/

const crypto = require('node:crypto');

const allowed = new Map();

function normalizeUrlForAllow(url) {
	try {
		const u = new URL(String(url || ''));
		u.hash = '';
		return u.toString();
	} catch {
		return String(url || '');
	}
}

function cleanupExpired(nowMs) {
	const now = Number.isFinite(nowMs) ? nowMs : Date.now();
	for (const [key, item] of allowed.entries()) {
		if (!item || item.expiresAt <= now) allowed.delete(key);
	}
}

function addTemporaryAllow(url, ttlSeconds) {
	cleanupExpired();
	const key = normalizeUrlForAllow(url);
	if (!key) return '';
	const token = crypto.randomBytes(16).toString('hex');
	const ttl = Number.isFinite(ttlSeconds) ? Math.max(30, ttlSeconds) : 300;
	allowed.set(key, {
		token,
		expiresAt: Date.now() + ttl * 1000,
	});
	return token;
}

function isTemporarilyAllowed(url) {
	cleanupExpired();
	const key = normalizeUrlForAllow(url);
	if (!key) return false;
	return allowed.has(key);
}

module.exports = {
	addTemporaryAllow,
	isTemporarilyAllowed,
	normalizeUrlForAllow,
};
