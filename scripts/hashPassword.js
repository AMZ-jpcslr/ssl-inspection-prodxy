#!/usr/bin/env node
/*
メモ
このスクリプトがやること
- ダッシュボード認証で使うパスワードを、平文ではなく scrypt のハッシュとして生成します。
- 生成結果は `config.local.json`（推奨）または `config.json` の `dashboardAuth` に貼り付けます。
- 併せてセッション署名に使う `sessionSecret` もランダム生成します。

原理（要点）
- `crypto.scryptSync()` で「パスワード + ランダムsalt」から派生鍵を作り、保存します。
- ダッシュボード側は保存済みパラメータ（N/r/p/keyLen）と salt を使って再計算し、
	timing-safe な比較で一致判定します（実装は `src/dashboard/auth.js`）。

使い方
- 例: `node scripts/hashPassword.js my-password`
	- 標準出力に JSON が出るので、その `dashboardAuth` を `config.local.json` に貼り付ける。
- 注意:
	- `passwordHash` と `sessionSecret` は“秘密”。`config.json`（共有）に入れず、`config.local.json` 推奨。
	- ここで生成した値は“復号できない”（平文パスワードは取り戻せない）。
*/

// crypto ... 暗号化機能ライブラリ
const crypto = require('node:crypto');

// バイト列を Base64 文字列にする（通常のBase64）。
// - config に埋め込むため、バイナリを文字列に変換して保存する。
// - ここはURLに載せる用途ではないので base64url にはしていない。
function b64(buf) {
	return Buffer.from(buf).toString('base64');
}

// セッション署名用の秘密鍵（sessionSecret）を生成する。
// - ランダム32バイトを hex 文字列にして返す（Cookie署名のHMAC鍵として使う）。
function generateSessionSecret() {
	return crypto.randomBytes(32).toString('hex');
}

// パスワードをscryptでハッシュ化する関数
// salt...ランダムなバイト列
// salt + パスワードをscryptにかけて派生鍵を生成、保存する→辞書攻撃に対抗
// opts...scryptのパラメータ（N:計算コスト/r/p:メモリ,並列性に関するパラメータ/keyLen:派生鍵の長さ）とsaltのバイト数、maxmem(メモリ上限)
function scryptHash(password, opts) {
	const salt = crypto.randomBytes(opts.saltBytes);
	const derived = crypto.scryptSync(password, salt, opts.keyLen, {
		N: opts.N,
		r: opts.r,
		p: opts.p,
		maxmem: opts.maxmem,
	});
	return {
		algorithm: 'scrypt',
		params: { N: opts.N, r: opts.r, p: opts.p, keyLen: opts.keyLen },
		saltBase64: b64(salt),
		hashBase64: b64(derived),
	};
}

// CLI のエントリポイント。
// - 引数で受け取った平文パスワードから、configへ貼り付けるJSON（dashboardAuth）を標準出力へ出す。
// - 実運用ではこのJSONは `config.local.json` に置くのが安全（秘密情報をGitに載せない）。
function main() {
	const password = process.argv[2];
	if (!password) {
		console.error('Usage: node scripts/hashPassword.js <password>');
		process.exitCode = 2;
		return;
	}

	const opts = {
		N: 16384,
		r: 8,
		p: 1,
		keyLen: 64,
		saltBytes: 16,
		maxmem: 64 * 1024 * 1024,
	};

	const phc = scryptHash(password, opts);
	const sessionSecret = generateSessionSecret();

	const out = {
		dashboardAuth: {
			enabled: true,
			username: 'admin',
			passwordHash: phc,
			sessionSecret,
			sessionTtlSeconds: 60 * 60 * 8,
		},
	};

	process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
}

main();
