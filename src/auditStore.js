/*
メモ
監査ログストア（JSONL）

目的
- 管理者の操作（ログイン/ログアウト/設定変更など）を監査ログとして永続化し、追跡できるようにする

原理（要点）
- 監査ログは JSONL（1行=1JSON）で追記し、ダッシュボード側で末尾N件を読み込みする。
- DBなしの最小実装のため、読み込みはファイル全体→末尾N件のslice（大規模化したら改善余地あり）。

監査ログとアクセスログの違い
- アクセスログ: プロキシが観測した通信（大量・自動的）
- 監査ログ: 管理者がダッシュボードで行った操作（少量・“誰が何をしたか”を残したい）
*/

const fs = require('node:fs');
const path = require('node:path');

// 指定された「ファイルパス」の親ディレクトリを作成する。
// - JSONLを追記したいだけでも、先にフォルダが無いと書き込みに失敗するため。
function ensureDirForFile(filePath) {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

// 監査ログをJSONLとして1行追記する。
// - obj は 1イベント分（例: login / logout / 設定変更）。
// - JSONLは「追記が簡単」「1行ずつ壊れても他に影響しにくい」という利点がある。
function appendAuditJsonl(filePath, obj) {
	ensureDirForFile(filePath);
	fs.appendFileSync(filePath, `${JSON.stringify(obj)}\n`, 'utf8');
}

// 監査ログJSONLの末尾N件を読み込む。
// - MVPのため「全体を読み→末尾だけslice」している（巨大化したら改善余地）。
// - 壊れた行（JSONとしてパースできない行）は無視して継続する。
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
