const fs = require('node:fs');
const path = require('node:path');

// Small JSONL store for access logs.
// Writes append one JSON object per line; reads return the latest N valid rows.
function ensureDirForFile(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function rotateJsonlIfNeeded(filePath, maxBytes) {
  const limit = Number.isFinite(maxBytes) ? Math.max(0, maxBytes) : 0;
  if (limit <= 0) return;
  try {
    if (!fs.existsSync(filePath)) return;
    const stat = fs.statSync(filePath);
    if (!stat.isFile() || stat.size < limit) return;
    const rotatedPath = `${filePath}.1`;
    try {
      fs.rmSync(rotatedPath, { force: true });
    } catch {
      // ignore
    }
    fs.renameSync(filePath, rotatedPath);
  } catch {
    // Logging must not stop the proxy if rotation fails.
  }
}

function appendJsonl(filePath, obj, opts) {
  ensureDirForFile(filePath);
  const options = opts && typeof opts === 'object' ? opts : {};
  rotateJsonlIfNeeded(filePath, Number(options.maxBytes));
  fs.appendFileSync(filePath, `${JSON.stringify(obj)}\n`, 'utf8');
}

function clearJsonl(filePath) {
  ensureDirForFile(filePath);
  fs.writeFileSync(filePath, '', 'utf8');
}

function parseJsonlLines(lines) {
  const entries = [];
  for (const line of lines) {
    try {
      entries.push(JSON.parse(line));
    } catch {
      // ignore malformed line
    }
  }
  return entries;
}

function readLastJsonlEntries(filePath, maxEntries) {
  const limit = Number.isFinite(maxEntries) ? Math.max(0, Math.floor(maxEntries)) : 0;
  if (limit === 0 || !fs.existsSync(filePath)) return [];

  const chunkSize = 64 * 1024;
  let fd;
  let raw = '';

  try {
    fd = fs.openSync(filePath, 'r');
    const stat = fs.fstatSync(fd);
    let position = stat.size;
    let newlineCount = 0;

    while (position > 0 && newlineCount <= limit) {
      const readSize = Math.min(chunkSize, position);
      position -= readSize;
      const buffer = Buffer.allocUnsafe(readSize);
      const bytesRead = fs.readSync(fd, buffer, 0, readSize, position);
      raw = buffer.subarray(0, bytesRead).toString('utf8') + raw;
      newlineCount = (raw.match(/\n/g) || []).length;
    }
  } catch {
    return [];
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore
      }
    }
  }

  const lines = raw.split(/\r?\n/).filter(Boolean);
  return parseJsonlLines(lines.slice(Math.max(0, lines.length - limit)));
}

module.exports = { appendJsonl, readLastJsonlEntries, clearJsonl };
