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
*/

const fs = require('node:fs');
const path = require('node:path');

function normalizeHostname(hostname) {
	return (hostname || '').toLowerCase().trim().replace(/\.$/, '');
}

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

function ensureDirForFile(filePath) {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

let configured = false;
let policyFilePath = path.resolve(process.cwd(), 'data/policy.json');
let blockDomains = [];
let lastLoadedAt = null;

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

function getPolicyFilePath() {
	return policyFilePath;
}

function getBlockDomains() {
	return blockDomains.slice();
}

function setBlockDomains(domains) {
	blockDomains = normalizeDomainList(domains);
	try {
		ensureDirForFile(policyFilePath);
		const payload = {
			blockDomains,
			updatedAt: new Date().toISOString(),
		};
		fs.writeFileSync(policyFilePath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
	} catch {
		// ignore write errors (prototype)
	}
	return getBlockDomains();
}

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
