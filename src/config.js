/*
メモ
設定ローダ

このファイルがやること
- `config.json` を読み込み、必要なら `config.local.json` を上書きマージする
- Docker 等を想定し、特定キーのみ環境変数で上書きできるようにする

原理（要点）
- プロトタイプのため、設定は「ファイル（JSON）を正」としつつ、
  実行環境差（ポートやログパス）だけを env で上書きできるようにする。
- `config.local.json` は `.gitignore` 前提で、機密（ダッシュボード認証情報など）をコミットしにくくする。

補足
- なぜ `config.local.json` がある？
  - `config.json` は共有したい設定（ポート、対象ドメイン等）
  - `config.local.json` は“個人/環境依存の秘密”（passwordHashやsessionSecretなど）
  - 秘密をGitにコミットしないため、ファイルを分けて上書きする。
- deepMerge の挙動
  - オブジェクトは「キーごとに再帰的に上書き」
  - 配列/数値/文字列などは「丸ごと置き換え」
    （例: domains配列を足したい場合は、配列マージではなく“完全に置換”になる点に注意）
*/

const fs = require('node:fs');
const path = require('node:path');

// 「普通のオブジェクトか？」を判定するユーティリティ。
// - null/配列を除外し、deepMerge で安全に扱える形だけを対象にする。
function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// 再帰的なマージ（deep merge）。
// - config.json（基本設定）に config.local.json（ローカル上書き）を重ねる用途。
// - 配列やプリミティブは「上書き」扱い、オブジェクト同士だけを再帰マージする。
function deepMerge(target, source) {
  if (!isPlainObject(target) || !isPlainObject(source)) return target;
  for (const [key, value] of Object.entries(source)) {
    if (isPlainObject(value) && isPlainObject(target[key])) {
      deepMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

// 設定ファイル（config.json）を読み込むモジュール
// - プロキシの待受ポート
// - ダッシュボードの待受ポート
// - ログ保存先
// - ドメインフィルタ/ブロック設定
// - ダッシュボード認証（有効時）
function loadConfig() {
  const configPath = path.resolve(process.cwd(), 'config.json');
  const raw = fs.readFileSync(configPath, 'utf8');
  const config = JSON.parse(raw);

  // Optional local override file (kept out of git via .gitignore).
  // Use for secrets like dashboardAuth.sessionSecret/passwordHash.
  const localConfigPath = path.resolve(process.cwd(), 'config.local.json');
  // Docker compose で `./config.local.json:/app/config.local.json` をマウントする場合、
  // ホスト側にファイルが無いと「ディレクトリ」が作られてマウントされることがあります。
  // その場合 readFileSync が EISDIR で落ちるので、“通常ファイルのときだけ読む”ようにしておきます。
  let localConfigIsFile = false;
  try {
    localConfigIsFile = fs.existsSync(localConfigPath) && fs.statSync(localConfigPath).isFile();
  } catch {
    localConfigIsFile = false;
  }

  if (localConfigIsFile) {
    try {
      const localRaw = fs.readFileSync(localConfigPath, 'utf8');
      const localConfig = JSON.parse(localRaw);
      deepMerge(config, localConfig);
    } catch (e) {
      const msg = e && e.message ? e.message : String(e);
      throw new Error(`Failed to load config.local.json: ${msg}`);
    }
  }

  // Allow environment overrides (useful for Docker).
  // Keep JSON as the source of truth unless an env var is explicitly set.
  // - コンテナ/CIではファイル編集が面倒なことがあるため、必要最小限だけenvで上書きできるようにする。
  // 注意:
  // - envは文字列なので Number(...) 変換が必要。
  // - “未設定なら上書きしない”を守ることで、意図せず設定が変わるのを防ぐ。
  if (process.env.PROXY_HOST) config.proxy = { ...(config.proxy || {}), host: process.env.PROXY_HOST };
  if (process.env.PROXY_PORT) config.proxy = { ...(config.proxy || {}), port: Number(process.env.PROXY_PORT) };
  if (process.env.DASHBOARD_HOST) config.dashboard = { ...(config.dashboard || {}), host: process.env.DASHBOARD_HOST };
  if (process.env.DASHBOARD_PORT) config.dashboard = { ...(config.dashboard || {}), port: Number(process.env.DASHBOARD_PORT) };
  if (process.env.DASHBOARD_PUBLIC_BASE_URL) {
    config.dashboard = { ...(config.dashboard || {}), publicBaseUrl: process.env.DASHBOARD_PUBLIC_BASE_URL };
  }
  if (process.env.LOG_PATH) config.logging = { ...(config.logging || {}), path: process.env.LOG_PATH };

  // Dashboard auth overrides
  // - 設定値は「存在する時だけ」上書きする（未設定ならJSONファイルの値を使う）。
  if (process.env.DASHBOARD_AUTH_ENABLED) {
    config.dashboardAuth = {
      ...(config.dashboardAuth || {}),
      enabled: String(process.env.DASHBOARD_AUTH_ENABLED).toLowerCase() === 'true',
    };
  }
  if (process.env.DASHBOARD_AUTH_USERNAME) {
    config.dashboardAuth = { ...(config.dashboardAuth || {}), username: process.env.DASHBOARD_AUTH_USERNAME };
  }
  if (process.env.DASHBOARD_AUTH_SESSION_SECRET) {
    config.dashboardAuth = { ...(config.dashboardAuth || {}), sessionSecret: process.env.DASHBOARD_AUTH_SESSION_SECRET };
  }

  return config;
}

module.exports = { loadConfig };
