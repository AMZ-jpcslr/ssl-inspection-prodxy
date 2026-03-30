/*
設定ローダ

このファイルがやること
- `config.json` を読み込み、必要なら `config.local.json` を上書きマージする
- Docker 等を想定し、特定キーのみ環境変数で上書きできるようにする

どういう原理で動くか（要点）
- プロトタイプのため、設定は「ファイル（JSON）を正」としつつ、
  実行環境差（ポートやログパス）だけを env で上書きできるようにしています。
- `config.local.json` は `.gitignore` 前提で、機密（ダッシュボード認証情報など）をコミットしにくくします。
*/

const fs = require('node:fs');
const path = require('node:path');

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

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
function loadConfig() {
  const configPath = path.resolve(process.cwd(), 'config.json');
  const raw = fs.readFileSync(configPath, 'utf8');
  const config = JSON.parse(raw);

  // Optional local override file (kept out of git via .gitignore).
  // Use for secrets like dashboardAuth.sessionSecret/passwordHash.
  const localConfigPath = path.resolve(process.cwd(), 'config.local.json');
  if (fs.existsSync(localConfigPath)) {
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
  if (process.env.PROXY_HOST) config.proxy = { ...(config.proxy || {}), host: process.env.PROXY_HOST };
  if (process.env.PROXY_PORT) config.proxy = { ...(config.proxy || {}), port: Number(process.env.PROXY_PORT) };
  if (process.env.DASHBOARD_HOST) config.dashboard = { ...(config.dashboard || {}), host: process.env.DASHBOARD_HOST };
  if (process.env.DASHBOARD_PORT) config.dashboard = { ...(config.dashboard || {}), port: Number(process.env.DASHBOARD_PORT) };
  if (process.env.LOG_PATH) config.logging = { ...(config.logging || {}), path: process.env.LOG_PATH };

  // Dashboard auth overrides
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
