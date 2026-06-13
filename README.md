# Web Browsing Inspection Proxy

Node.js で作られた、学習・検証用の Web 閲覧監視プロキシです。
ブラウザの通信をこのプロキシ経由にすると、アクセス先、HTTP メソッド、ステータス、リクエスト/レスポンス本文の一部、PII 検出結果などをログに残し、ダッシュボードで確認できます。

HTTPS も SSL inspection(MITM) で確認できますが、端末にローカル CA 証明書を信頼させる必要があります。

## 重要な注意

このプログラムは HTTPS 通信の中身を見られる強い権限を持ちます。実環境で使う場合は、利用者への説明と同意、社内規程、監査、鍵管理、ログの保持期間、アクセス制御を必ず整備してください。

まずは自分の検証用端末、検証用ブラウザプロファイル、検証用サイトで試すことをおすすめします。

## できること

- HTTP/HTTPS 通信をプロキシ経由で中継する
- アクセスログを `data/access.log.jsonl` に保存する
- ダッシュボードでログを一覧・検索・詳細表示する
- 指定ドメインをブロックする
- フィッシング疑い URL に警告ページを出す
- メールアドレス、カード番号らしき文字列、電話番号らしき文字列を検出する
- 画像アップロードや画像レスポンスをファイルとして保存する
- 管理操作を監査ログに保存する

## 全体像

```text
ブラウザ
  ↓ HTTP/HTTPS プロキシ設定: 127.0.0.1:8080
このプログラム
  ├─ Proxy:     127.0.0.1:8080
  ├─ Dashboard: http://127.0.0.1:3001/
  ├─ Access log: data/access.log.jsonl
  └─ Local CA:   .http-mitm-proxy/certs/ca.pem
```

## 必要なもの

- Node.js 18 以上
- npm
- Git
- HTTPS の中身まで確認したい場合は、証明書を端末に登録できる権限

Docker で動かす場合は Docker Desktop などの Docker 実行環境も必要です。

## はじめてのチュートリアル

ここでは、ローカル PC で起動して、ブラウザから通信を流し、ダッシュボードでログを見るところまで進めます。

### 1. 依存関係をインストールする

リポジトリのルートで実行します。

```bash
npm install
```

### 2. プログラムを起動する

```bash
npm start
```

起動すると、次の 2 つが同時に立ち上がります。

- プロキシ: `127.0.0.1:8080`
- ダッシュボード: `http://127.0.0.1:3001/`

初回起動後、HTTPS アクセスを行うと `.http-mitm-proxy/` 配下にローカル CA やドメイン別証明書が生成されます。

### 3. ダッシュボードの初回設定をする

ブラウザで次を開きます。

```text
http://127.0.0.1:3001/
```

`config.json` ではダッシュボード認証が有効になっています。まだパスワードが未設定の場合は、自動的に初回セットアップ画面へ移動します。

セットアップ画面で次を入力してください。

- username: 例 `admin`
- password: 8 文字以上の任意のパスワード
- confirm password: 同じパスワード

作成すると、Git 管理外の `config.local.json` に認証情報が保存されます。

保存後は、いったん `npm start` を止めて、もう一度起動してください。

```bash
npm start
```

その後、`http://127.0.0.1:3001/login` からログインできます。

### 4. ブラウザをプロキシ経由にする

ブラウザ、または OS のプロキシ設定で、HTTP と HTTPS のプロキシを次のように設定します。

```text
HTTP proxy:  127.0.0.1
HTTP port:   8080
HTTPS proxy: 127.0.0.1
HTTPS port:  8080
```

Chrome / Edge を使う場合、多くの環境では Windows のプロキシ設定を変更します。

検証が終わったら、必ずプロキシ設定を元に戻してください。戻し忘れると、このプログラムを停止したあとにブラウザが通信できなくなります。

### 5. HTTP サイトで動作確認する

まずは証明書登録が不要な HTTP サイトで確認します。

```text
http://example.com/
```

ダッシュボード `http://127.0.0.1:3001/` を開くと、アクセスログが表示されます。

`config.json` の初期設定では、ログ対象は `google.com` と `yahoo.co.jp` に絞られています。HTTP サイトで確実にログを見たい場合は、次のように一時的に `filtering.mode` を `all` に変更してください。

```json
{
  "filtering": {
    "mode": "all",
    "domains": ["google.com", "yahoo.co.jp"]
  }
}
```

変更後は `npm start` を再起動してください。

### 6. HTTPS の中身を確認する

HTTPS の内容を確認するには、プロキシが生成したローカル CA を端末に信頼させます。

CA 証明書の場所:

```text
.http-mitm-proxy/certs/ca.pem
```

Windows の管理者 PowerShell で登録する例:

```powershell
certutil -addstore -f root .\.http-mitm-proxy\certs\ca.pem
```

登録後、ブラウザで HTTPS サイトを開きます。

```text
https://www.google.com/
```

ダッシュボードにログが出れば成功です。詳細ページでは、設定されたサイズ上限の範囲でリクエスト/レスポンス本文も確認できます。

Firefox は独自の証明書ストアを使うことがあります。その場合は Firefox 側にも CA を取り込んでください。

### 7. ブロック機能を試す

初期設定では `tiktok.com` がブロック対象です。

プロキシ設定を有効にしたブラウザで次にアクセスします。

```text
https://www.tiktok.com/
```

ブラウザにブロックページが表示され、ダッシュボードのログには `blocked: true` が記録されます。

ブロック対象はダッシュボード上部の Admin セクションで編集できます。保存すると、プロキシを再起動せずに反映されます。

## よく使うコマンド

```bash
# 起動
npm start

# 開発時も同じ起動処理
npm run dev

# ダッシュボード用パスワードハッシュを生成
npm run auth:hash -- your-password

# 生成済みの MITM 証明書/鍵キャッシュを削除
npm run clean:mitm

# Docker で起動
docker compose up --build
```

## 設定ファイル

主な設定は `config.json` にあります。

機密情報や個人環境ごとの差分は `config.local.json` に置きます。`config.local.json` は `.gitignore` で除外されているため、パスワードハッシュや `sessionSecret` を保存する場所として使います。

起動時は次の順番で設定されます。

1. `config.json` を読み込む
2. `config.local.json` があれば上書きする
3. 一部の値を環境変数で上書きする

### プロキシとダッシュボード

```json
{
  "proxy": {
    "host": "0.0.0.0",
    "port": 8080
  },
  "dashboard": {
    "host": "127.0.0.1",
    "port": 3001
  }
}
```

### ログ対象ドメイン

```json
{
  "filtering": {
    "mode": "allowlist",
    "domains": ["google.com", "yahoo.co.jp"]
  }
}
```

- `mode: "allowlist"`: `domains` に一致する通信だけログに残す
- `mode: "all"`: すべての通信をログに残す

### ブロック対象ドメイン

```json
{
  "blocking": {
    "domains": ["tiktok.com"]
  }
}
```

ダッシュボードから変更した内容は `data/policy.json` に保存されます。一度保存すると、以後は `data/policy.json` の内容が優先されます。

### 本文取得とファイル保存

```json
{
  "inspection": {
    "maxBodyBytes": 4096,
    "captureRequestBody": true,
    "captureResponseBody": true,
    "bodyCaptureDomains": ["google.com", "yahoo.co.jp"],
    "captureRequestFiles": true,
    "captureResponseFiles": true,
    "maxFileBytes": 2097152,
    "fileSaveDir": "./data/files",
    "fileCaptureDomains": ["google.com", "yahoo.co.jp"]
  }
}
```

- `maxBodyBytes`: ログに保存する本文の最大バイト数
- `bodyCaptureDomains`: 本文取得対象のドメイン
- `captureRequestFiles`: 画像アップロードを保存する
- `captureResponseFiles`: 画像レスポンスを保存する
- `maxFileBytes`: 保存するファイルの最大バイト数
- `fileSaveDir`: 保存先ディレクトリ

`bodyCaptureDomains: []` にすると、すべてのドメインで本文取得します。機微情報がログに残る可能性が高くなるため、検証目的以外ではおすすめしません。

### フィッシング警告

```json
{
  "phishing": {
    "enabled": true,
    "suspiciousDomains": [],
    "officialDomains": ["google.com", "yahoo.co.jp"],
    "trustedDomains": ["google.com", "yahoo.co.jp"],
    "keywords": ["login", "verify", "account", "password", "payment"],
    "suspiciousTlds": ["zip", "mov", "click", "work", "top", "xyz"],
    "lookalikeMaxDistance": 1,
    "requireKeywordWithHeuristics": true
  }
}
```

フィッシング判定はプロトタイプ用のヒューリスティックです。正式なセキュリティ製品の判定精度を想定したものではありません。

## ダッシュボードで見られるもの

ダッシュボード:

```text
http://127.0.0.1:3001/
```

監査ログ:

```text
http://127.0.0.1:3001/audit
```

ダッシュボードでは、次のような情報を確認できます。

- アクセス時刻
- ドメイン
- URL
- HTTP メソッド
- ステータスコード
- HTTPS かどうか
- ブロックされたかどうか
- PII 検出結果
- 保存ファイルへのリンク
- リクエスト/レスポンス本文の詳細ページ

Health セクションでは、認証設定、ローカル CA の有無、ログ保存先への書き込み可否、本文取得対象ドメインなどを確認できます。

## ログファイル

アクセスログ:

```text
data/access.log.jsonl
```

監査ログ:

```text
data/audit.log.jsonl
```

ブロックポリシー:

```text
data/policy.json
```

保存ファイル:

```text
data/files/
```

`data/` は生成物なので Git 管理外です。

## Docker で動かす

```bash
docker compose up --build
```

起動後の URL はローカル起動時と同じです。

- プロキシ: `127.0.0.1:8080`
- ダッシュボード: `http://127.0.0.1:3001/`

`docker-compose.yml` では、次のディレクトリをホスト側に永続化します。

- `./data:/app/data`
- `./.http-mitm-proxy:/app/.http-mitm-proxy`

Docker 環境でも、HTTPS の中身を見るにはホスト側に生成された `.http-mitm-proxy/certs/ca.pem` を端末の信頼ストアへ登録してください。

社内ネットワークなどで上流側も SSL inspection されている場合、コンテナ内の Node.js が上流証明書を検証できず `UNABLE_TO_VERIFY_LEAF_SIGNATURE` が出ることがあります。その場合は社内ルート CA を PEM 形式で用意し、`NODE_EXTRA_CA_CERTS` で渡してください。

## トラブルシューティング

### ダッシュボードにログが出ない

確認すること:

- ブラウザの HTTP/HTTPS プロキシが `127.0.0.1:8080` になっているか
- `npm start` が起動したままか
- `config.json` の `filtering.mode` が `allowlist` の場合、アクセス先が `filtering.domains` に含まれているか
- HTTPS の場合、ローカル CA を信頼済みか

すべての通信を一時的にログに出したい場合は、`filtering.mode` を `all` にして再起動してください。

### HTTPS サイトで証明書エラーになる

多くの場合、ブラウザが `.http-mitm-proxy/certs/ca.pem` を信頼していません。

Windows の Chrome / Edge では、Windows の「信頼されたルート証明機関」に登録してください。

```powershell
certutil -addstore -f root .\.http-mitm-proxy\certs\ca.pem
```

Firefox の場合は Firefox 側の証明書設定も確認してください。

### `HTTPS_CLIENT_ERROR` / `socket hang up` / `certificate unknown` が多い

ブラウザがプロキシの発行した証明書を信頼できず、接続を切っている可能性があります。

`.http-mitm-proxy/certs/ca.pem` を信頼ストアに登録できているか確認してください。

### `ERR_OSSL_X509_KEY_VALUES_MISMATCH` が出る

生成済みの証明書と秘密鍵の組み合わせが壊れている可能性があります。

プロキシを止めてから、次を実行してください。

```bash
npm run clean:mitm
npm start
```

この操作で `.http-mitm-proxy/` が削除され、次回アクセス時に再生成されます。CA も作り直されるため、端末への CA 登録もやり直してください。

### Docker で `UNABLE_TO_VERIFY_LEAF_SIGNATURE` が出る

コンテナ内の Node.js が、上流サーバーの TLS 証明書チェーンを検証できていない状態です。

社内ルート CA などを `./certs/extra-ca.pem` に置き、`docker-compose.yml` で次のように渡してください。

```yaml
volumes:
  - ./certs:/app/certs:ro
environment:
  NODE_EXTRA_CA_CERTS: /app/certs/extra-ca.pem
```

`NODE_TLS_REJECT_UNAUTHORIZED=0` は検証を無効化するため、推奨しません。

### ダッシュボードが重い

リクエスト/レスポンス本文が大きいと、詳細表示が重くなることがあります。

対処:

- `inspection.maxBodyBytes` を小さくする
- `bodyCaptureDomains` を必要なドメインだけに絞る
- 不要なログは Admin セクションの `clear access log` で削除する

## 生成されるファイルについて

`.http-mitm-proxy/` には、ローカル CA、ドメイン別証明書、秘密鍵などが生成されます。

`http-mitm-proxy` は HTTPS を MITM するため、アクセス先ドメインごとに証明書や鍵を生成してキャッシュします。いろいろなサイトにアクセスすると `.http-mitm-proxy/certs/` や `.http-mitm-proxy/keys/` にファイルが増えますが、これは正常です。

不要になったら次のコマンドで削除できます。

```bash
npm run clean:mitm
```

## ディレクトリ構成

```text
.
├── README.md
├── config.json
├── config.local.json        # ローカル設定。Git 管理外
├── docker-compose.yml
├── Dockerfile
├── package.json
├── scripts/
│   └── hashPassword.js
├── src/
│   ├── main.js              # プロキシ本体の起動と通信検査
│   ├── config.js            # 設定読み込み
│   ├── pii.js               # PII 検出
│   ├── phishing.js          # フィッシング疑い判定
│   └── dashboard/           # ダッシュボード
├── data/                    # ログや保存ファイル。Git 管理外
└── .http-mitm-proxy/        # MITM 用証明書/鍵。Git 管理外
```

## 検証後に戻すこと

検証が終わったら、次を忘れずに戻してください。

1. ブラウザまたは OS のプロキシ設定をオフにする
2. 必要がなければ登録したローカル CA を信頼ストアから削除する
3. 機微情報を含む可能性がある `data/` のログを削除する

ログを消すだけなら、ダッシュボードの Admin セクションから `clear access log` を使えます。
