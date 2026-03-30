# Web閲覧監視プロキシ（Node.js + MITM + Dashboard）のコンテナ実行用 Dockerfile
#
# - 依存関係を `npm ci` でインストールし、`npm start` でプロキシ(8080)/ダッシュボード(3001)を起動。
# - ルートCAのバンドル（ca-certificates）を入れて、上流TLS検証ができるようにしている。
#
# 原理（要点）
# - `http-mitm-proxy` はMITM用の証明書をコンテナ内に生成/保持するため、
#   それを永続化したい場合は docker-compose の volume を使う。

FROM node:20-bookworm-slim

WORKDIR /app

# Ensure system CA bundle is present for upstream TLS verification
RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

# Install deps first for better layer caching
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY config.json ./config.json

EXPOSE 8080 3001

CMD ["npm", "start"]
