import { unzipSync } from "fflate";

const UTF8 = new TextDecoder("utf-8");
const ZIP_EOCD_SIGNATURE = 0x06054b50;
const ZIP_CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;

function readU16(bytes, offset) {
  if (offset + 2 > bytes.length) throw new Error("ZIP 文件结构不完整");
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function readU32(bytes, offset) {
  if (offset + 4 > bytes.length) throw new Error("ZIP 文件结构不完整");
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
}

function findEndOfCentralDirectory(bytes) {
  const minimumOffset = Math.max(0, bytes.length - 65557);
  for (let offset = bytes.length - 22; offset >= minimumOffset; offset -= 1) {
    if (readU32(bytes, offset) === ZIP_EOCD_SIGNATURE) return offset;
  }
  throw new Error("无效或不受支持的 ZIP 文件");
}

function normalizeArchivePath(name) {
  if (!name || name.includes("\\") || name.startsWith("/") || /^[A-Za-z]:/.test(name)) {
    throw new Error("ZIP 中包含不安全的文件路径");
  }
  const directory = name.endsWith("/");
  const trimmed = directory ? name.slice(0, -1) : name;
  if (!trimmed) return { path: "", directory: true };
  const parts = trimmed.split("/");
  if (parts.some((part) => !part || part === "." || part === ".." || /[\u0000-\u001F]/.test(part))) {
    throw new Error("ZIP 中包含不安全的文件路径");
  }
  return { path: parts.join("/"), directory };
}

function centralDirectoryEntries(bytes, limits) {
  const eocd = findEndOfCentralDirectory(bytes);
  const disk = readU16(bytes, eocd + 4);
  const centralDirectoryDisk = readU16(bytes, eocd + 6);
  const entriesOnDisk = readU16(bytes, eocd + 8);
  const entryCount = readU16(bytes, eocd + 10);
  const directorySize = readU32(bytes, eocd + 12);
  const directoryOffset = readU32(bytes, eocd + 16);
  const commentLength = readU16(bytes, eocd + 20);

  if (disk !== 0 || centralDirectoryDisk !== 0 || entriesOnDisk !== entryCount) {
    throw new Error("不支持分卷 ZIP 文件");
  }
  if (eocd + 22 + commentLength !== bytes.length || entryCount === 0) {
    throw new Error("ZIP 文件结构无效");
  }
  if (entryCount > limits.maxFiles || directoryOffset + directorySize > eocd) {
    throw new Error("ZIP 文件数量或目录大小超出限制");
  }

  const entries = [];
  const seen = new Set();
  let offset = directoryOffset;
  let totalUncompressedBytes = 0;
  for (let index = 0; index < entryCount; index += 1) {
    if (readU32(bytes, offset) !== ZIP_CENTRAL_DIRECTORY_SIGNATURE) throw new Error("ZIP 文件目录无效");
    const flags = readU16(bytes, offset + 8);
    const compression = readU16(bytes, offset + 10);
    const compressedBytes = readU32(bytes, offset + 20);
    const uncompressedBytes = readU32(bytes, offset + 24);
    const nameLength = readU16(bytes, offset + 28);
    const extraLength = readU16(bytes, offset + 30);
    const fileCommentLength = readU16(bytes, offset + 32);
    const recordLength = 46 + nameLength + extraLength + fileCommentLength;
    if (offset + recordLength > directoryOffset + directorySize) throw new Error("ZIP 文件目录无效");
    if (compressedBytes === 0xFFFFFFFF || uncompressedBytes === 0xFFFFFFFF) throw new Error("不支持 ZIP64 文件");
    if (flags & 0x0001) throw new Error("不支持加密 ZIP 文件");
    if (![0, 8].includes(compression)) throw new Error("ZIP 包含不受支持的压缩格式");

    const rawName = UTF8.decode(bytes.subarray(offset + 46, offset + 46 + nameLength));
    const { path, directory } = normalizeArchivePath(rawName);
    if (!directory) {
      if (seen.has(path)) throw new Error("ZIP 中包含重复文件路径");
      if (uncompressedBytes > limits.maxFileBytes) throw new Error(`文件 ${path} 超出单文件大小限制`);
      totalUncompressedBytes += uncompressedBytes;
      if (totalUncompressedBytes > limits.maxUnzippedBytes) throw new Error("ZIP 解压后的总大小超出限制");
      seen.add(path);
      entries.push({ path, uncompressedBytes });
    }
    offset += recordLength;
  }
  if (offset !== directoryOffset + directorySize) throw new Error("ZIP 文件目录长度无效");
  return { entries, totalUncompressedBytes };
}

function selectSiteRoot(entries) {
  const rootIndex = entries.find((entry) => /^index\.html?$/i.test(entry.path));
  if (rootIndex) return { prefix: "", indexPath: rootIndex.path };
  const candidates = entries.filter((entry) => /\/index\.html?$/i.test(entry.path));
  if (candidates.length !== 1) throw new Error("ZIP 根目录必须包含唯一的 index.html 或 index.htm");
  const indexPath = candidates[0].path;
  return { prefix: indexPath.slice(0, indexPath.lastIndexOf("/") + 1), indexPath };
}

export function contentTypeForPath(path) {
  const extension = path.split(".").pop().toLowerCase();
  const types = {
    html: "text/html;charset=UTF-8", htm: "text/html;charset=UTF-8", css: "text/css;charset=UTF-8",
    js: "text/javascript;charset=UTF-8", mjs: "text/javascript;charset=UTF-8", cjs: "text/javascript;charset=UTF-8",
    json: "application/json;charset=UTF-8", map: "application/json;charset=UTF-8", webmanifest: "application/manifest+json;charset=UTF-8",
    svg: "image/svg+xml", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif",
    webp: "image/webp", avif: "image/avif", ico: "image/x-icon", bmp: "image/bmp",
    woff: "font/woff", woff2: "font/woff2", ttf: "font/ttf", otf: "font/otf", eot: "application/vnd.ms-fontobject",
    wasm: "application/wasm", txt: "text/plain;charset=UTF-8", xml: "application/xml;charset=UTF-8",
    pdf: "application/pdf", mp3: "audio/mpeg", ogg: "audio/ogg", wav: "audio/wav", mp4: "video/mp4", webm: "video/webm"
  };
  return types[extension] || "application/octet-stream";
}

export function decodeBase64(base64) {
  if (typeof base64 !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(base64) || base64.length % 4 !== 0) {
    throw new Error("ZIP 上传数据无效");
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

export function encodeBase64(bytes) {
  const chunkSize = 0x8000;
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

export function unpackStaticSiteZip(bytes, limits) {
  if (!(bytes instanceof Uint8Array) || !bytes.length) throw new Error("ZIP 文件为空");
  if (bytes.length > limits.maxZipBytes) throw new Error("ZIP 文件超过大小限制");
  const { entries } = centralDirectoryEntries(bytes, limits);
  const { prefix, indexPath } = selectSiteRoot(entries);
  let unzipped;
  try { unzipped = unzipSync(bytes); }
  catch { throw new Error("ZIP 文件无法解压"); }

  const assets = [];
  for (const entry of entries) {
    if (prefix && !entry.path.startsWith(prefix)) continue;
    const body = unzipped[entry.path];
    if (!(body instanceof Uint8Array) || body.byteLength !== entry.uncompressedBytes) {
      throw new Error(`ZIP 中的文件 ${entry.path} 解压校验失败`);
    }
    const relativePath = entry.path === indexPath ? "index.html" : entry.path.slice(prefix.length);
    if (!relativePath || relativePath === "index.htm") continue;
    assets.push({ path: relativePath, body, contentType: contentTypeForPath(relativePath) });
  }
  if (!assets.some((asset) => asset.path === "index.html")) throw new Error("ZIP 中缺少可发布的首页文件");
  return assets;
}

export function safeAssetPath(path) {
  try {
    const decoded = decodeURIComponent(path);
    return normalizeArchivePath(decoded).path;
  } catch { return null; }
}
