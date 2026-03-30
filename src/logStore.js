/*
メモ
JSONL ログストア

このファイルがやること
- ログを JSONL（1行=1JSON）で追記する
- ダッシュボード表示用に「末尾N件」を読み込む

原理（要点）
- DBを導入せず、ファイル追記で永続化する最小構成。
- 読み込みはMVPの割り切りとして“全体を読み→末尾N件をslice”（大規模化したら改善余地あり）。
*/

const fs = require('node:fs');
const path = require('node:path');

// JSONL（1行=1JSON）でログを永続化する簡易ストア
// MVPでは「追記」と「末尾N件読み込み」だけ。
function ensureDirForFile(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function appendJsonl(filePath, obj) {
  ensureDirForFile(filePath);
  fs.appendFileSync(filePath, `${JSON.stringify(obj)}\n`, 'utf8');
}

function readLastJsonlEntries(filePath, maxEntries) {
  if (!fs.existsSync(filePath)) return [];

  // MVPなので、末尾N件を効率的に読み込む方法は考慮しない（ファイル全体を読む）。
  // 将来的に、ファイルが大きくなったときに末尾N件だけを効率的に読む方法を検討する（例: 逆から読む、ログローテーションするなど）。
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

module.exports = { appendJsonl, readLastJsonlEntries };
