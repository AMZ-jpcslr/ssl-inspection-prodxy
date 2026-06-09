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

このファイルを読むときの“全体像”
1) ログイン時（server.jsの /login）
	 - フォームで受け取った平文パスワードを `verifyScryptPassword()` で照合
	 - OKなら「セッションCookie」を発行する
		 tokenの形: v1.<username>.<exp>.<sig>
			 - username: ログインしているユーザー名（このプロトタイプでは固定でも可）
			 - exp: 有効期限（UNIX秒）
			 - sig: 上の2つを材料にHMACで作った“改ざん検出用の署名”
2) リクエスト受信時（server.jsの requireAuth）
	 - Cookieヘッダを `parseCookies()` で分解して token を取り出す
	 - `verifyDashboardSession()` で「期限切れでない」「署名が一致」をチェック

重要な注意点
- ここでやっている署名（HMAC）は“暗号化”ではない。
	Cookieの中身（username/exp）は見ようと思えば見えるが、改ざんすると検出される。
- timingSafeEqual は「文字列比較の時間差」から情報が漏れるのを避けるために使う。
	（超重要な秘密を比較するところでは、早期returnの比較より安全）
*/

// crypto ... 暗号化機能ライブラリ
const crypto = require('node:crypto');

// バイト列を Base64URL にエンコードする。
// - CookieやURLに載せやすいように `+` `/` `=` を使わない表現にする。
// - 署名（mac）のバイナリを「安全なASCII文字列」にしてtokenに埋め込むため。
function base64UrlEncode(buf) {
	return Buffer.from(buf)
		.toString('base64')
		.replaceAll('+', '-')
		.replaceAll('/', '_')
		.replaceAll('=', '');
}

// Base64URL 文字列を元のバイト列（Buffer）へ戻す。
// - Base64は4の倍数長が必要なので、必要なら `=` を付けて復元してからデコードする。
function base64UrlDecode(s) {
	const str = String(s || '').replaceAll('-', '+').replaceAll('_', '/');
	const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
	return Buffer.from(str + pad, 'base64');
}

// Cookieヘッダ文字列を「名前→値」のオブジェクトにする。
// - 例: "a=1; b=hello" -> { a: "1", b: "hello" }
// - ダッシュボードでは `dashboard_session` を取り出すために使う。
// なぜ必要？
// - Node/ExpressはCookieを“自動で常にパースしてくれる”わけではないため、最小実装として自前で分解する。
// - ここはRFCのすべてをカバーする厳密パーサではない（プロトタイプの割り切り）。
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

// ログイン時に「署名」を作る（Cookie本文そのものではなく、MAC部分だけ）。
// - payload = "username.exp"（exp は UNIX epoch seconds）
// - sig = HMAC-SHA256(payload, sessionSecret) を Base64URL で表現
// - 署名があることで、Cookieが改ざんされても検出できる
// なぜこの形？
// - username/exp をtoken内にそのまま入れると、サーバはDB無しで復元できる（=ステートレスっぽい）。
// - ただし「入れてある値を信用してよい」ようにするため、必ずHMACで“改ざん検出”を付ける。
// - sessionSecret はサーバだけが知る秘密。攻撃者がtokenを書き換えても、正しいsigは作れない。
function signDashboardSession(username, expEpochSeconds, sessionSecret) {
	const payload = `${username}.${expEpochSeconds}`;
	const mac = crypto.createHmac('sha256', String(sessionSecret)).update(payload).digest();
	return base64UrlEncode(mac);
}

// 受信したセッションCookieを検証する。
// - 署名が一致するか（改ざんされていないか）
// - 有効期限が切れていないか
// 返り値: OKならtrue、NGならfalse
// 攻撃・失敗例（これを防ぎたい）
// - Cookieを書き換えて exp を未来にする（期限延長）
// - Cookieを書き換えて username を admin にする（権限昇格）
// → 署名が一致しないので弾かれる。
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

// パスワードをscryptハッシュと照合する関数
// hashPassword.jsで作成したsaltとpasswordHashを受け取って、新しくrequestにあるパスワードを使用し同じパラメータでscryptをかけて比較する
// 正しいなら保存済みpasswordHashと一致するはずなので、timingSafeEqualで比較して結果を返す
// 重要:
// - Cookieに「パスワード」は入らない。ログイン時にフォームから受け取ったパスワードだけを照合する。
// - config 側に保存するのは salt/params/derivedKey のみ（平文は保存しない）。
// なぜscrypt？（初心者向け）
// - パスワードをそのままhashすると、総当たり（辞書攻撃）されやすい。
// - scrypt は「わざと計算/メモリコストを重くする」ことで、攻撃者の試行回数を下げる目的の関数。
// - salt は「同じパスワードでも結果を変える」ためのランダム値（レインボーテーブル対策）。
// - N/r/p は“重さ”のパラメータ（値が大きいほど照合は遅くなるが安全寄り）。
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

function generateSessionSecret() {
	return crypto.randomBytes(32).toString('hex');
}

function createScryptPasswordHash(password) {
	const opts = {
		N: 16384,
		r: 8,
		p: 1,
		keyLen: 64,
		saltBytes: 16,
		maxmem: 64 * 1024 * 1024,
	};
	const salt = crypto.randomBytes(opts.saltBytes);
	const derived = crypto.scryptSync(String(password), salt, opts.keyLen, {
		N: opts.N,
		r: opts.r,
		p: opts.p,
		maxmem: opts.maxmem,
	});
	return {
		algorithm: 'scrypt',
		params: { N: opts.N, r: opts.r, p: opts.p, keyLen: opts.keyLen },
		saltBase64: Buffer.from(salt).toString('base64'),
		hashBase64: Buffer.from(derived).toString('base64'),
	};
}

module.exports = {
	parseCookies,
	signDashboardSession,
	verifyDashboardSession,
	verifyScryptPassword,
	generateSessionSecret,
	createScryptPasswordHash,
};
