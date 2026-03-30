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
*/

const crypto = require('node:crypto');

function b64(buf) {
	return Buffer.from(buf).toString('base64');
}

function generateSessionSecret() {
	return crypto.randomBytes(32).toString('hex');
}

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
