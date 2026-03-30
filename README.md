## 概要

- Node.js製の「明示プロキシ」+ HTTPSのSSL inspection(MITM) を行うプロトタイプです
- アクセスログを `data/access.log.jsonl` に永続化し、ダッシュボードで一覧表示します
- ドメインブロック（例: `tiktok.com`）を行えます
- HTTPS通信は（サイズ上限付きで）リクエスト/レスポンスのボディも取得し、ログ/ダッシュボードで確認できます

重要: 実環境でのSSL inspectionは強い権限とプライバシー影響を伴います。社内規程・同意・鍵管理・監査の整備が前提です。

## 実装状況（要件対応）

本READMEは提出用に「今回どこまで実装したか」を明確にするため、課題要件（docs/CHALLENGE.md）に沿って実装状況を整理しています。

### 実装した機能

- HTTPS通信の傍受（MITM）
	- 明示プロキシとしてブラウザにHTTP/HTTPSプロキシ設定を行い、CONNECT + MITM で復号して検査します
	- 初回起動で `.http-mitm-proxy/certs/ca.pem` を生成し、これを端末側で信頼することでHTTPSが閲覧可能になります
- 基本ログ記録（永続化）
	- `timestamp/domain/URL/method/status` を JSONL として `data/access.log.jsonl` に追記します
- ログ閲覧ダッシュボード
	- `http://127.0.0.1:3001/` で直近ログを表示します
- 特定ドメインの通信フィルタリング（推奨要件）
	- `filtering.mode=allowlist` と `filtering.domains` で「ログ対象ドメイン」を絞れます
- アクセスブロック（推奨要件）
	- `tiktok.com` など、ブロック対象ドメインへのアクセスは 403 のブロックページを返します
- 発展: ブロック対象のカスタマイズ（ダッシュボードから）
	- Adminセクションで編集→保存すると再起動なしで即時反映されます
	- 永続化先は `data/policy.json` です
- 発展: 監査ログ（管理操作の記録・閲覧）
	- `data/audit.log.jsonl` にログイン/ログアウト/設定変更を追記します
	- `http://127.0.0.1:3001/audit` で閲覧できます
- 推奨: PII検出・警告表示（メールアドレス）
	- URL（クエリ含む）・リクエスト本文・レスポンス本文（テキスト系Content-Typeのみ、取得できた範囲）から検出し、ダッシュボードで警告表示します
	- 表示はマスク（例: `u***@example.com`）し、必要時のみ詳細ページで確認できます

- 発展: レスポンスボディの検査（受信側のPII検出）
	- レスポンス本文（HTML/JSON等のテキスト系Content-Typeで取得できた範囲）も検査対象にしています
	- 注意: 取得はサイズ上限付きで、圧縮等の条件により検出はベストエフォートです
- 推奨: ダッシュボード認証
	- `dashboardAuth.enabled: true` の場合、ログインなしにUIへアクセスできません（scryptハッシュ + 署名付きcookie）
- 推奨: Docker化
	- `docker compose up --build` で起動できます（ログ/証明書キャッシュはvolumeで永続化）
- 画像（ファイル）保存（ログ肥大化対策）
	- `multipart/form-data` の画像アップロード（image/*）や、画像レスポンス（設定で有効化）を `data/files/` に保存し、ログには `/files/...` の参照を残します

### 実装していない機能（理由）

- 透過プロキシ（Transparent Proxy）としての構成
	- 理由: ネットワーク機器/OS側の設定（ルーティング、iptables/WinDivert等）や環境依存が大きく、1週間のプロトタイプ範囲では再現性が担保しづらいため
- 発展: リクエスト内容のキーワード/正規表現ブロック
	- 理由: 本文取得と同時に「リアルタイム遮断」する設計（ストリーム処理・誤検知・ユーザー体験・監査）が重く、まずはドメインブロック + PII検出の可視化を優先したため
- 発展: 管理者向けリアルタイム通知（WebSocket/Slack/メール等）
	- 理由: 通知先の外部依存（Slack/Webhook/SMTP等）と運用設計が必要で、課題デモの最小範囲を超えるため
- 発展: 統計・レポート（グラフ、ランキング等）
	- 理由: 永続化をJSONLで割り切っているため、集計/検索のためのDB導入やUI実装が追加で必要になり、優先度を下げたため
- 発展: 高度なPII検出（クレカ/Luhn、電話番号、マイナンバー等）
	- 理由: 誤検知/漏れの調整とテストが必要で、まずはメールアドレスに絞って“検知→警告表示”の最小ループを作ったため
- 発展: DLPポリシー（ファイル内容検査・形式に応じたアクション選択）
	- 理由: 本文/ファイルの取得範囲拡大がプライバシー影響を大きくするため、保持/アクセス制御/監査などの運用設計が先に必要になるため
- 発展: 対話型ブロック確認（従業員側で送信/キャンセル選択）
	- 理由: ブラウザ側との対話UIやタイムアウト制御が必要で、プロキシ単体MVPから外れるため
- 発展: ドメインカテゴリ分類
	- 理由: カテゴリDBや更新運用（分類の根拠/更新頻度）が必要で、課題期間では実装・説明コストが高いため
- 発展: ユーザー/端末識別（クライアントIP統計等）
	- 理由: 実運用ではNAT/プロキシ連鎖/認証連携など設計が必要で、プロトタイプではログ項目を課題必須に集中したため
- 発展: アラートルール設定（条件式、履歴、通知）
	- 理由: ルール管理/評価/通知を一式で作る必要があり、まずはログ閲覧と監査ログを優先したため
- 発展: HTTP/2対応の明示的検証
	- 理由: ブラウザ/サイト依存で検証手順を安定させる必要があり、プロキシの基本動作（HTTPS傍受・ログ・ブロック）を優先したため
- 発展: 大容量ファイルアップロードの検出（例: 10MB超警告/ブロック）
	- 理由: 大容量ストリームの扱い（性能/保存/プライバシー）を設計して段階的に追加すべきで、今回は画像の安全な保存（上限付き）に留めたため
- 発展: CA証明書の安全な管理（期限監視・ローテーション手順）
	- 理由: 本課題はローカル環境でのデモが中心のため、まずはMITM動作を成立させる導線（CA生成/信頼）を優先したため

- 発展: APIアクセス制御
	- 理由: 今回は外部向けAPIとして公開するエンドポイントを用意しておらず、まずはダッシュボード（UI）を認証で保護する最小構成を優先したため

## 使い方（ローカル）

### 1) 依存関係インストール

`npm install`

### 2) 起動

`npm start`

- Proxy: `0.0.0.0:8080`（設定は `config.json`）
- Dashboard: `http://127.0.0.1:3001/`

## 推奨: ダッシュボード認証

`dashboardAuth.enabled: true` にすると、ダッシュボードにログインが必要になります。

推奨運用:
- 共有してよい設定は `config.json`
- パスワード関連の機密情報（`sessionSecret` / `passwordHash`）は Git 管理外の `config.local.json` に保存

このリポジトリでは `config.local.json` が存在する場合、起動時に `config.json` を読み込んだ後で `config.local.json` の内容で上書きします。

### 1) パスワードハッシュ生成

`npm run auth:hash -- <password>`

出力された JSON の `dashboardAuth` を `config.local.json` に貼り付けてください（`sessionSecret` も含みます）。

※ `config.local.json` は `.gitignore` で除外されるため、機密情報をコミットしにくくなります。

### 2) 反映して起動

`npm start`

ログインURL: `http://127.0.0.1:3001/login`

注意:
- 本プロトタイプは最小実装のため、ユーザーは1つ（`dashboardAuth.username`）のみ想定です
- `dashboardAuth.enabled: true` なのに `passwordHash` / `sessionSecret` が無い場合は 500 を返します

## ブロック対象ドメインのカスタマイズ（ダッシュボードから）

ダッシュボードのトップページ上部の **Admin** セクションから、ブロック対象ドメインを編集できます。

- 保存すると **プロキシへ即時反映** されます（再起動不要）
- 永続化先は `./data/policy.json` です（起動時に読み込まれます）

補足: 既定では `config.json` の `blocking.domains` が初期値として読み込まれ、`policy.json` を保存すると以降はその内容が有効になります。

## 監査ログ（管理操作の記録）

管理者の操作は監査ログとして JSONL で保存されます。

- 監査ログ保存先: `./data/audit.log.jsonl`
- ダッシュボード閲覧URL: `http://127.0.0.1:3001/audit`

記録する操作（最小）:
- ログイン/ログアウト
- ブロック対象ドメインの変更

## Docker化

`docker compose up --build`

- Proxy: `0.0.0.0:8080`
- Dashboard: `http://127.0.0.1:3001/`

補足:
- `data/` と `.http-mitm-proxy/` はボリュームでホスト側に永続化します
- HTTPS可視化をする場合は、ホスト側に生成される `.http-mitm-proxy/certs/ca.pem` を信頼ストアに登録してください

### 3) ブラウザのプロキシ設定

ブラウザ（もしくはOS）のHTTP/HTTPSプロキシを `127.0.0.1:8080` に設定します。

### 4) （HTTPS可視化をする場合）ローカルCAを信頼

初回起動時にプロキシがローカルCAを生成します。
ブラウザが証明書警告を出さずにHTTPSを閲覧できるように、生成されたCA証明書を端末の信頼ストアに登録してください。

- CA証明書: `.http-mitm-proxy/certs/ca.pem`

#### 補足: `.http-mitm-proxy/` 配下に大量のpem/keyができる件

`http-mitm-proxy` はHTTPSをMITMするため、アクセス先ドメインごとに証明書（pem）や鍵（key）を生成し、再利用のためにディスクへキャッシュします。
そのため、色々なサイトにアクセスすると `.http-mitm-proxy/certs/` や `.http-mitm-proxy/keys/` にファイルが増えるのは正常です。

- これらは生成物なので、Gitにはコミットしない（このリポジトリでは `.gitignore` で除外しています）
- ローカル検証で不要になったら `.http-mitm-proxy/` を削除してもOK（次回起動/アクセス時に再生成されます）

補足: この手順は端末のセキュリティに影響します。検証用端末・検証用プロファイルでのみ実施してください。

## トラブルシューティング

### `ERR_OSSL_X509_KEY_VALUES_MISMATCH` / `OPEN_HTTPS_SERVER_ERROR`

`http-mitm-proxy` が生成する MITM 用証明書（`.http-mitm-proxy/certs/*.pem`）と秘密鍵（`.http-mitm-proxy/keys/*.key`）の組が壊れている/食い違っている時に、HTTPS サーバーの起動で失敗して出るエラーです。

対処（推奨）:
- プロキシを停止 → `npm run clean:mitm` → `npm start`

※ `npm run clean:mitm` は `.http-mitm-proxy/`（生成済みの cert/key キャッシュ）を削除し、次回アクセス時に再生成させます。

注意:
- `.http-mitm-proxy` を削除すると CA（`ca.pem`）も作り直されるため、端末の信頼ストアへの登録をやり直してください（上の「ローカルCAを信頼」参照）

### Proxyログに `HTTPS_CLIENT_ERROR` / `socket hang up` / `certificate unknown` が大量に出る

これは多くの場合、ブラウザ（HTTPSクライアント）が
「プロキシがMITMで発行した証明書を信頼できない」ために接続をリセット（`ECONNRESET`）している状態です。

対処:
- `.http-mitm-proxy/certs/ca.pem` を「信頼されたルート証明機関」として登録できているか確認
- Chrome/Edge は基本的に **Windowsの証明書ストア** を参照するため、ブラウザ内だけに入れても効かない場合があります

Windows（管理者）での登録例:
- `certutil -addstore -f root .\\.http-mitm-proxy\\certs\\ca.pem`

※ Firefox は独自の証明書ストアを使うことがあるため、Firefox利用時はFirefox側にもCA取り込みが必要になる場合があります。

### Docker起動時に `UNABLE_TO_VERIFY_LEAF_SIGNATURE` / `unable to verify the first certificate` が出る

Dockerコンテナ内の Node.js が **上流サーバー（google等）のTLS証明書チェーンを検証できていない** 状態です。
社内ネットワークで SSL inspection（社内プロキシ）が動いている場合、ホストOSでは信頼済みの「社内ルートCA」が **コンテナ内には入っていない** ために起きがちです。

対処（推奨）:
- 社内ルートCA証明書（PEM形式）を用意し、`NODE_EXTRA_CA_CERTS` でコンテナに渡す

例（docker-compose.yml）:
- `./certs/extra-ca.pem` を用意
- compose に以下を設定
	- volume: `./certs:/app/certs:ro`
	- env: `NODE_EXTRA_CA_CERTS=/app/certs/extra-ca.pem`

注意:
- `NODE_TLS_REJECT_UNAUTHORIZED=0` のような回避は動きますが、セキュリティ的に危険なので推奨しません

### 管理画面が重い（details 展開が重い）

request/response body が大きいと、HTML に埋め込まれる文字列が巨大になってブラウザが重くなります。

- 対策: 管理画面では body/form-fields を一定長でプレビュー表示にしています（完全な内容は `data/access.log.jsonl` 側に残ります）
- 必要なら `data/access.log.jsonl` を直接参照するか、ファイル保存が有効な場合は `/files/...` の参照（ログ内）を見てください

## HTTPSボディ取得について

必須要件の「HTTPS通信の内容（リクエストURL、ボディ等）取得」に対応するため、以下をログに含めます。

- リクエストボディ（例: POST）: `requestBodyText` または `requestBodyBase64`
- レスポンスボディ（例: HTML/JSON）: `responseBodyText` または `responseBodyBase64`
- いずれもサイズ上限付き（デフォルト: 4096 bytes）で、超過時は `*BodyTruncated: true`

注意:
- `Content-Encoding: gzip` 等のとき、ボディは圧縮されたまま（base64）になる場合があります
- 実環境ではプライバシー影響が大きいので、取得範囲・保持期間・アクセス制御を必ず検討してください

## PII検出（メールアドレス）について

推奨要件の「PII検出・警告表示」に対応するため、URL（クエリ含む）およびリクエストボディ（取得できた範囲）から
メールアドレス（例: `user@example.com`）らしき文字列を検出し、ダッシュボードに警告表示します。

発展要件の「レスポンスボディの検査」にも対応し、レスポンスボディ（HTML/JSON等のテキスト系Content-Typeで取得できた範囲）にも
メールアドレスが含まれる場合は検出して警告表示します（受信側のPII検出）。

- ログ(JSONL)には `piiEmailDetected`, `piiEmailCount`, `piiEmailSamples`（マスク済みサンプル）等が記録されます
- 受信（レスポンス）で検出した場合は `piiEmailInResponse: true` が記録されます
- ダッシュボードは一覧を軽く保つため、検出サンプルは行内に埋め込まず `view` リンクから別ページで表示します
- 注意: ボディがサイズ上限で打ち切られている場合、検出は取得できた範囲に限定されます

### 設定（config.json）

必要に応じて `config.json` に `inspection` を追加して挙動を調整できます。

例:

```json
{
	"inspection": {
		"maxBodyBytes": 4096,
		"captureRequestBody": true,
		"captureResponseBody": true,
		"bodyCaptureDomains": ["google.com", "yahoo.co.jp"],

		"captureRequestFiles": true,
		"captureResponseFiles": false,
		"maxFileBytes": 2097152,
		"fileSaveDir": "./data/files",
		"fileCaptureDomains": ["google.com", "yahoo.co.jp"]
	}
}
```


補足:
- `bodyCaptureDomains` を省略した場合は、`filtering.domains` をボディ取得対象として扱います（安全のためのデフォルト）
- `bodyCaptureDomains: []` を指定すると、すべてのドメインでボディ取得します（機微情報がログに残る可能性があるため注意）

## 画像（ファイル）保存について

ボディをJSONLにbase64で埋め込むとログが肥大化しやすいため、画像などはファイルとして保存し、ログには参照（URL）だけを残す方式をサポートします。

- 対象: 
	- リクエスト: `multipart/form-data` のアップロード画像（`Content-Type: image/*` のパートのみ）
	- レスポンス: `Content-Type: image/*` のレスポンス（設定で有効化した場合）
- 保存先: `inspection.fileSaveDir`（デフォルト `./data/files`）
- 上限: `inspection.maxFileBytes` を超えた場合は **保存せずskip**（中途半端にtruncateしません）
- 参照: ダッシュボードが `/files/*` を静的配信し、ログには `/files/<file>` の形で記録されます

注意:
- 画像以外のアップロード（PDFなど）はデフォルトで保存しません（`image/*` のみ）
- 実環境では保持期間・アクセス制御・保存領域・個人情報の取り扱いを必ず設計してください

## ディレクトリ構造

```
.
├── README.md
├── docs/
│   ├── CHALLENGE.md      # 課題内容
│   └── DESIGN.md         # 設計ドキュメント（テンプレート）
└── src/                  # ソースコード
```

## 提出前の動作確認（デモ）チェックリスト

- `npm start` で Proxy(8080) と Dashboard(3001) が起動する
- ブラウザのHTTP/HTTPSプロキシを `127.0.0.1:8080` に設定して、`https://www.google.com/` と `https://www.yahoo.co.jp/` を閲覧できる
- ダッシュボード `http://127.0.0.1:3001/` で最新ログが表示される（timestamp/domain/URL/method/status）
- `tiktok.com`（またはブロック設定に入れたドメイン）へのアクセスが 403 のブロックページになる
- Adminのブロック編集→保存後、**再起動なし**でブロックが即時反映され、`data/policy.json` が更新される
- 監査ログ `http://127.0.0.1:3001/audit` に login/logout と設定変更が記録され、`data/audit.log.jsonl` が追記される
- PII（メールアドレス）を含むURL/本文を送った場合にダッシュボードで警告表示される（必要なら `captureRequestBody` 等を有効化）
- 画像アップロード等を行った場合に、設定次第で `data/files/` に保存され `/files/...` 経由で参照できる

