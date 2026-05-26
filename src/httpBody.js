/*
メモ
HTTP 本文のデコード（PIIスキャン用）

このファイルがやること
- Content-Type を簡易パースして MIME/charset を取り出す
- MIME から“テキストっぽいか”を判定する
- Content-Encoding（br/gzip/deflate）をベストエフォートに展開して UTF-8 文字列へ変換する

原理（要点）
- PII検出はテキストが前提なので、text系以外（画像/PDFなど）は原則スキップ。
- 圧縮展開は例外や巨大展開に備え、最大出力サイズを制限。
- 先頭のバイト列から“バイナリっぽさ”を雑に判定し、無理な文字列化を避けます（完全判定ではない）。

補足（なぜこんなに慎重？）
- Content-Encoding（gzip/br等）は「ネットワーク上で小さく送るための圧縮」。
	PIIスキャンしたいなら展開が必要だが、展開するとサイズが急増することがある。
- なので `maxOutputLength` で“展開爆弾”やメモリ逼迫を避ける。
- `looksBinary()` は完璧ではないが、バイナリをUTF-8にしてゴミ文字列で誤検出するのを減らす。
*/

const zlib = require('node:zlib');

// Content-Type ヘッダをパースして MIME タイプと charset を抽出する簡易ロジック
// 例: "text/html; charset=utf-8" -> { mime: "text/html", charset: "utf-8" }
// 例: "application/json" -> { mime: "application/json", charset: "" }
function parseContentType(value) {
	const s = String(value || '').trim();
	if (!s) return { mime: '', charset: '' };
	const [mimePart, ...params] = s.split(';').map((p) => p.trim());
	let charset = '';
	for (const p of params) {
		const m = /^charset=(.+)$/i.exec(p);
		if (m) {
			charset = m[1].trim();
			break;
		}
	}
	return { mime: mimePart.toLowerCase(), charset: charset.toLowerCase() };
}

// MIMEタイプから「テキストっぽいか」を判定する簡易ロジック
// - PIIスキャンは文字列が前提なので、バイナリっぽいものを避ける入口として使う。
function isTextLikeMime(mime) {
	const m = String(mime || '').toLowerCase();
	if (!m) return false;
	if (m.startsWith('text/')) return true;
	if (m.includes('json')) return true;
	if (m.includes('xml')) return true;
	if (m.includes('javascript')) return true;
	if (m === 'application/x-www-form-urlencoded') return true;
	return false;
}

// バイナリっぽいかを簡易判定するロジック（完全ではない）
// 無理にテキスト化しない方が良さそうな場合に使用する（例: 画像やPDFなど）
// - NUL(0x00)が混ざる/制御文字が多い等を雑に検知する。
function looksBinary(buffer) {
	if (!buffer || buffer.length === 0) return false;
	const sampleLen = Math.min(buffer.length, 64);
	let suspicious = 0;
	for (let i = 0; i < sampleLen; i++) {
		const b = buffer[i];
		if (b === 0x00) return true;
		if (b < 0x09) suspicious++;
		if (b > 0x7e && b < 0xa0) suspicious++;
	}
	return suspicious / sampleLen > 0.2;
}

// Decode a body (optionally compressed) into a UTF-8 string for PII scanning.
// - Only attempts decode for text-like MIME types.
// - Best-effort; returns '' on failure.
// - Output is capped to avoid excessive memory usage.
// 追加メモ:
// - Content-Encoding: br/gzip/deflate をベストエフォートに展開する。
// - 展開後にバイナリっぽければ '' を返し、無理に文字列化しない。
function decodeTextBodyForPii(buf, contentTypeHeader, contentEncodingHeader) {
	try {
		if (!buf || buf.length === 0) return '';
		const { mime } = parseContentType(contentTypeHeader);
		if (!isTextLikeMime(mime)) return '';
		const encoding = String(contentEncodingHeader || '').toLowerCase();
		const maxOutputLength = 256 * 1024;

		// 展開は“ベストエフォート”。失敗したら catch で '' を返す。
		// - ここで例外を投げると、プロキシ全体のログ処理に影響が出るため。

		let out = null;
		if (encoding.includes('br')) {
			out = zlib.brotliDecompressSync(buf, { maxOutputLength });
		} else if (encoding.includes('gzip')) {
			out = zlib.gunzipSync(buf, { maxOutputLength });
		} else if (encoding.includes('deflate')) {
			out = zlib.inflateSync(buf, { maxOutputLength });
		}

		const candidate = out && out.length ? out : buf;
		if (looksBinary(candidate)) return '';
		return candidate.toString('utf8');
	} catch {
		return '';
	}
}

module.exports = {
	parseContentType,
	isTextLikeMime,
	looksBinary,
	decodeTextBodyForPii,
};
