/*
メモ
監査ログストア（JSONL）

目的
- 管理者の操作（ログイン/ログアウト/設定変更など）を監査ログとして永続化し、追跡できるようにする

原理（要点）
- 監査ログは JSONL（1行=1JSON）で追記し、ダッシュボード側で末尾N件を読み込みする。
- DBなしの最小実装のため、読み込みはファイル全体→末尾N件のslice（大規模化したら改善余地あり）。
*/

const fs = require('node:fs');
const path = require('node:path');

function ensureDirForFile(filePath) {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function appendAuditJsonl(filePath, obj) {
	ensureDirForFile(filePath);
	fs.appendFileSync(filePath, `${JSON.stringify(obj)}\n`, 'utf8');
}

function readLastAuditEntries(filePath, maxEntries) {
	if (!fs.existsSync(filePath)) return [];
	const raw = fs.readFileSync(filePath, 'utf8');
	const lines = raw.split(/\r?\n/).filter(Boolean);
	const slice = lines.slice(Math.max(0, lines.length - maxEntries));
	const entries = [];
	for (const line of slice) {
		try {
			entries.push(JSON.parse(line));
		} catch {
			// ignore malformed line
		}
	}
	return entries;
}

module.exports = { appendAuditJsonl, readLastAuditEntries };
