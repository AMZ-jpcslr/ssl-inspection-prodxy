/*
メモ
動的ポリシーストア（最小実装）

目的
- ダッシュボードから更新される「ブロック対象ドメイン一覧」をメモリ上に保持し、プロキシの判定に即時反映する
- 必要に応じてファイル（JSON）に永続化し、再起動後も復元する

原理（要点）
- JSONファイルを起動時に読み込んでメモリにキャッシュし、更新時に同期的に書き戻し。
- ランタイムでは「メモリ上の配列」を参照するため、リクエストごとにファイルI/Oは発生しない。
- ドメインは小文字化・末尾ドット除去で正規化して保存。

補足
- なぜ“メモリにキャッシュ”する？
	- プロキシはリクエストごとにブロック判定するので、毎回ファイルを読むと遅い。
	- 代わりに、ダッシュボードで更新があった時だけファイルへ書く。
- なぜ同期I/O（readFileSync/writeFileSync）？
	- MVPでロジックを簡単にするため（ただし高負荷用途では非同期やロックが必要）。
*/

const fs = require('node:fs');
const path = require('node:path');

// ホスト名の正規化:
// - 小文字化
// - 前後空白の除去
// - 末尾のドット（FQDNの表記揺れ）を削除
function normalizeHostname(hostname) {
	return (hostname || '').toLowerCase().trim().replace(/\.$/, '');
}

// ドメインリストの正規化:
// - 空/重複を除外
// - 表記ゆれを統一
function normalizeDomainList(domains) {
	if (!Array.isArray(domains)) return [];
	const out = [];
	const seen = new Set();
	for (const d of domains) {
		const s = normalizeHostname(String(d || ''));
		if (!s) continue;
		if (seen.has(s)) continue;
		seen.add(s);
		out.push(s);
	}
	return out;
}

// JSONファイルを書き出す前に、親ディレクトリを作る。
function ensureDirForFile(filePath) {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

let configured = false;
let policyFilePath = path.resolve(process.cwd(), 'data/policy.json');
let blockDomains = [];
let lastLoadedAt = null;

// ポリシーストアを初期化する（1回だけ）。
// - 起動時に呼ばれ、JSONの永続化パスとデフォルト値を設定する。
// - 既にポリシーファイルが存在すれば、それを読み込んで復元する。
function configurePolicyStore({ filePath, defaultBlockDomains } = {}) {
	if (configured) return;
	configured = true;
	policyFilePath = path.resolve(process.cwd(), String(filePath || 'data/policy.json'));
	blockDomains = normalizeDomainList(defaultBlockDomains);

	try {
		if (fs.existsSync(policyFilePath)) {
			const raw = fs.readFileSync(policyFilePath, 'utf8');
			const json = JSON.parse(raw);
			if (json && Array.isArray(json.blockDomains)) {
				blockDomains = normalizeDomainList(json.blockDomains);
			}
			lastLoadedAt = new Date().toISOString();
		}
	} catch {
		// ignore and keep defaults
	}
}

// 現在使っているポリシーファイルのパス（絶対パス）を返す。
function getPolicyFilePath() {
	return policyFilePath;
}

// 現在のブロックドメイン一覧を返す（外から破壊されないようコピー）。
function getBlockDomains() {
	return blockDomains.slice();
}

// ブロックドメイン一覧を更新し、JSONファイルにも保存する。
// - ダッシュボードの "Blocked domains" フォーム保存がこの関数を呼ぶ。
// - ここで更新したメモリ上の配列は、プロキシ本体（src/main.js）の判定にも即時反映される。
function setBlockDomains(domains) {
	blockDomains = normalizeDomainList(domains);
	try {
		ensureDirForFile(policyFilePath);
		const payload = {
			blockDomains,
			updatedAt: new Date().toISOString(),
		};
		// ここでの書き込み失敗は、プロトタイプでは致命にしない。
		// - 失敗してもメモリ上のブロックリストは更新済みなので、動作は継続できる。
		fs.writeFileSync(policyFilePath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
	} catch {
		// ignore write errors (prototype)
	}
	return getBlockDomains();
}

// 初期化済みか（ダッシュボード/プロキシが二重初期化しないためのガード）。
function isPolicyStoreConfigured() {
	return configured;
}

module.exports = {
	configurePolicyStore,
	getPolicyFilePath,
	getBlockDomains,
	setBlockDomains,
	isPolicyStoreConfigured,
	normalizeDomainList,
};
