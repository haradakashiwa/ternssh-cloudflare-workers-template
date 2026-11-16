import bcryptPbkdf from "bcrypt-pbkdf";
import { concat, encodeString, readUint32, toSSHMPInt } from "./utils";

const OPENSSH_MAGIC = new TextEncoder().encode("openssh-key-v1\0");

const KEY_BYTES: Record<string, number> = {
  "aes128-ctr": 16,
  "aes192-ctr": 24,
  "aes256-ctr": 32,
};

const ECDSA_CURVES: Record<
  string,
  { webCurve: "P-256" | "P-384" | "P-521"; hash: "SHA-256" | "SHA-384" | "SHA-512"; size: number }
> = {
  "ecdsa-sha2-nistp256": { webCurve: "P-256", hash: "SHA-256", size: 32 },
  "ecdsa-sha2-nistp384": { webCurve: "P-384", hash: "SHA-384", size: 48 },
  "ecdsa-sha2-nistp521": { webCurve: "P-521", hash: "SHA-512", size: 66 },
};

const OID_ED25519 = [0x06, 0x03, 0x2b, 0x65, 0x70];
const OID_RSA = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256 = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384 = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_P521 = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];

export interface SSHSigningKey {
  algorithm: string;
  publicKeyBlob: Uint8Array;
  sign(data: Uint8Array): Promise<Uint8Array>;
}

function readBuffer(data: Uint8Array, offset: number): { value: Uint8Array; next: number } {
  const len = readUint32(data, offset);
  const start = offset + 4;
  const end = start + len;
  if (end > data.length) {
    throw new Error("私钥格式损坏：字段越界");
  }
  return { value: data.subarray(start, end), next: end };
}

function readCString(data: Uint8Array, offset: number): { value: string; next: number } {
  const field = readBuffer(data, offset);
  return { value: new TextDecoder().decode(field.value), next: field.next };
}

function normalizeCipherName(name: string): string {
  if (name === "none") return "none";
  if (name.startsWith("aes") && name.includes("-")) return name;
  const match = /^aes(\d+)(ctr|cbc)$/i.exec(name);
  if (match) return `aes${match[1]}-${match[2].toLowerCase()}`;
  throw new Error(`不支持的私钥加密算法: ${name}`);
}

export function pemToRaw(pem: string): Uint8Array {
  const normalized = pem.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const b64 = normalized
    .split("\n")
    .filter((line) => !line.startsWith("-----"))
    .join("")
    .replace(/\s+/g, "");
  return Uint8Array.from(atob(b64), (char) => char.charCodeAt(0));
}

export function getOpenSSHKeyCipher(pem: string): string | null {
  try {
    const raw = pemToRaw(pem);
    return readOpenSSHEnvelope(raw).cipher;
  } catch {
    return null;
  }
}

export function isEncryptedOpenSSHPrivateKey(pem: string): boolean {
  const cipher = getOpenSSHKeyCipher(pem);
  return cipher !== null && cipher !== "none";
}

function readOpenSSHEnvelope(raw: Uint8Array): {
  cipher: string;
  kdfName: string;
  kdfOptions: Uint8Array;
  publicSection: Uint8Array;
  privateSection: Uint8Array;
} {
  if (raw.length < OPENSSH_MAGIC.length) {
    throw new Error("私钥数据太短");
  }
  for (let i = 0; i < OPENSSH_MAGIC.length; i++) {
    if (raw[i] !== OPENSSH_MAGIC[i]) {
      throw new Error("不支持的私钥格式");
    }
  }

  let offset = OPENSSH_MAGIC.length;
  const cipherField = readCString(raw, offset);
  const cipher = normalizeCipherName(cipherField.value);
  offset = cipherField.next;

  const kdfField = readCString(raw, offset);
  const kdfName = kdfField.value;
  offset = kdfField.next;

  const kdfOptionsField = readBuffer(raw, offset);
  const kdfOptions = kdfOptionsField.value;
  offset = kdfOptionsField.next;

  const numKeys = readUint32(raw, offset);
  offset += 4;
  if (numKeys !== 1) throw new Error("仅支持单密钥文件");

  const publicField = readBuffer(raw, offset);
  offset = publicField.next;

  const privateField = readBuffer(raw, offset);

  return {
    cipher,
    kdfName,
    kdfOptions,
    publicSection: publicField.value,
    privateSection: privateField.value,
  };
}

function parseKdfOptions(data: Uint8Array): { salt: Uint8Array; rounds: number } {
  let offset = 0;
  const saltField = readBuffer(data, offset);
  offset = saltField.next;
  const rounds = readUint32(data, offset);
  return { salt: saltField.value, rounds };
}

async function decryptPrivateSection(
  encrypted: Uint8Array,
  cipher: string,
  kdfName: string,
  kdfOptions: Uint8Array,
  passphrase: string,
): Promise<Uint8Array> {
  if (cipher === "none") return encrypted;

  const keyLen = KEY_BYTES[cipher];
  if (!keyLen) {
    throw new Error(`不支持的私钥加密算法: ${cipher}`);
  }
  if (kdfName !== "bcrypt") {
    throw new Error(`不支持的 KDF: ${kdfName}`);
  }
  if (!passphrase) {
    throw new Error("私钥已加密，请输入私钥密码");
  }

  const { salt, rounds } = parseKdfOptions(kdfOptions);
  const ivLen = 16;
  const keyIv = new Uint8Array(keyLen + ivLen);
  const passBytes = new TextEncoder().encode(passphrase);
  const result = bcryptPbkdf.pbkdf(
    passBytes,
    passBytes.length,
    salt,
    salt.length,
    keyIv,
    keyIv.length,
    rounds,
  );
  if (result !== 0) {
    throw new Error("私钥密码派生失败");
  }

  const key = keyIv.slice(0, keyLen);
  const iv = keyIv.slice(keyLen, keyLen + ivLen);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-CTR", length: keyLen * 8 },
    false,
    ["decrypt"],
  );
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-CTR", counter: iv, length: 128 },
    cryptoKey,
    encrypted,
  );
  const plain = new Uint8Array(decrypted);

  if (plain.length < 8) {
    throw new Error("私钥格式损坏：解密后数据太短");
  }
  const check1 = readUint32(plain, 0);
  const check2 = readUint32(plain, 4);
  if (check1 !== check2) {
    throw new Error("私钥密码错误");
  }

  return plain;
}

function stripLeadingZeros(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  return bytes.subarray(start);
}

function rawBytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function bytesToBase64Url(bytes: Uint8Array): string {
  return rawBytesToBase64Url(stripLeadingZeros(bytes));
}

async function exportJwk(key: CryptoKey): Promise<JsonWebKey> {
  return (await crypto.subtle.exportKey("jwk", key)) as JsonWebKey;
}

function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  return Uint8Array.from(atob(padded + pad), (char) => char.charCodeAt(0));
}

function mpintToBigInt(bytes: Uint8Array): bigint {
  const raw = stripLeadingZeros(bytes);
  if (raw.length === 0) return 0n;
  let hex = "";
  for (let i = 0; i < raw.length; i++) {
    hex += raw[i].toString(16).padStart(2, "0");
  }
  return BigInt(`0x${hex}`);
}

function bigIntToBytes(value: bigint): Uint8Array {
  if (value < 0n) throw new Error("私钥格式损坏：负整数");
  if (value === 0n) return new Uint8Array([0]);
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function padLeft(bytes: Uint8Array, size: number): Uint8Array {
  const raw = stripLeadingZeros(bytes);
  if (raw.length > size) {
    throw new Error("私钥格式损坏：整数过长");
  }
  if (raw.length === size) return raw;
  const out = new Uint8Array(size);
  out.set(raw, size - raw.length);
  return out;
}

function wrapSignature(algorithm: string, signature: Uint8Array): Uint8Array {
  return concat(encodeString(algorithm), encodeString(signature));
}

function buildEd25519PKCS8(seed: Uint8Array): Uint8Array {
  const oid = new Uint8Array([0x06, 0x03, 0x2b, 0x65, 0x70]);
  const seedOctet = new Uint8Array([0x04, seed.length, ...seed]);
  const innerOctet = new Uint8Array([0x04, seedOctet.length, ...seedOctet]);
  const algoSeq = new Uint8Array([0x30, oid.length, ...oid]);
  const version = new Uint8Array([0x02, 0x01, 0x00]);
  const totalLen = version.length + algoSeq.length + innerOctet.length;
  return new Uint8Array([0x30, totalLen, ...version, ...algoSeq, ...innerOctet]);
}

async function importEd25519(seed: Uint8Array, publicKeyBlob: Uint8Array): Promise<SSHSigningKey> {
  const signingKey = await crypto.subtle.importKey(
    "pkcs8",
    buildEd25519PKCS8(seed),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  return {
    algorithm: "ssh-ed25519",
    publicKeyBlob,
    async sign(data) {
      const raw = new Uint8Array(await crypto.subtle.sign("Ed25519", signingKey, data));
      return wrapSignature("ssh-ed25519", raw);
    },
  };
}

async function importRsa(params: {
  n: Uint8Array;
  e: Uint8Array;
  d: Uint8Array;
  p: Uint8Array;
  q: Uint8Array;
  iqmp: Uint8Array;
  publicKeyBlob: Uint8Array;
}): Promise<SSHSigningKey> {
  const d = mpintToBigInt(params.d);
  const p = mpintToBigInt(params.p);
  const q = mpintToBigInt(params.q);
  const jwk: JsonWebKey = {
    kty: "RSA",
    n: bytesToBase64Url(params.n),
    e: bytesToBase64Url(params.e),
    d: bytesToBase64Url(params.d),
    p: bytesToBase64Url(params.p),
    q: bytesToBase64Url(params.q),
    dp: bytesToBase64Url(bigIntToBytes(d % (p - 1n))),
    dq: bytesToBase64Url(bigIntToBytes(d % (q - 1n))),
    qi: bytesToBase64Url(params.iqmp),
  };
  const signingKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
    false,
    ["sign"],
  );
  return {
    algorithm: "rsa-sha2-512",
    publicKeyBlob: params.publicKeyBlob,
    async sign(data) {
      const raw = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signingKey, data));
      return wrapSignature("rsa-sha2-512", raw);
    },
  };
}

async function importEcdsa(
  keyType: keyof typeof ECDSA_CURVES,
  d: Uint8Array,
  publicPoint: Uint8Array,
  publicKeyBlob: Uint8Array,
): Promise<SSHSigningKey> {
  const curve = ECDSA_CURVES[keyType];
  if (!curve) {
    throw new Error(`不支持的密钥类型: ${keyType}`);
  }
  if (publicPoint.length !== 1 + curve.size * 2 || publicPoint[0] !== 0x04) {
    throw new Error("私钥格式损坏：ECDSA 公钥点无效");
  }
  const x = publicPoint.subarray(1, 1 + curve.size);
  const y = publicPoint.subarray(1 + curve.size);
  const jwk: JsonWebKey = {
    kty: "EC",
    crv: curve.webCurve,
    x: rawBytesToBase64Url(padLeft(x, curve.size)),
    y: rawBytesToBase64Url(padLeft(y, curve.size)),
    d: rawBytesToBase64Url(padLeft(d, curve.size)),
  };
  const signingKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: curve.webCurve },
    false,
    ["sign"],
  );
  return {
    algorithm: keyType,
    publicKeyBlob,
    async sign(data) {
      const raw = new Uint8Array(
        await crypto.subtle.sign({ name: "ECDSA", hash: curve.hash }, signingKey, data),
      );
      const half = raw.length / 2;
      const sshSig = concat(toSSHMPInt(raw.subarray(0, half)), toSSHMPInt(raw.subarray(half)));
      return wrapSignature(keyType, sshSig);
    },
  };
}

async function parseOpenSSHSigningKey(pem: string, passphrase?: string): Promise<SSHSigningKey> {
  const envelope = readOpenSSHEnvelope(pemToRaw(pem));
  const privateSection = await decryptPrivateSection(
    envelope.privateSection,
    envelope.cipher,
    envelope.kdfName,
    envelope.kdfOptions,
    passphrase ?? "",
  );

  if (privateSection.length < 8) {
    throw new Error("私钥格式损坏：私钥区太短");
  }
  const check1 = readUint32(privateSection, 0);
  const check2 = readUint32(privateSection, 4);
  if (check1 !== check2) {
    throw new Error(envelope.cipher === "none" ? "私钥格式损坏" : "私钥密码错误");
  }

  let offset = 8;
  const keyTypeField = readCString(privateSection, offset);
  const keyType = keyTypeField.value;
  offset = keyTypeField.next;

  if (keyType === "ssh-ed25519") {
    const pubField = readBuffer(privateSection, offset);
    offset = pubField.next;
    const privField = readBuffer(privateSection, offset);
    if (privField.value.length < 32) {
      throw new Error("私钥格式损坏：Ed25519 种子长度不足");
    }
    const publicKeyBlob =
      envelope.publicSection.length > 0
        ? envelope.publicSection
        : concat(encodeString("ssh-ed25519"), encodeString(pubField.value));
    return importEd25519(privField.value.subarray(0, 32), publicKeyBlob);
  }

  if (keyType === "ssh-rsa") {
    const n = readBuffer(privateSection, offset);
    offset = n.next;
    const e = readBuffer(privateSection, offset);
    offset = e.next;
    const d = readBuffer(privateSection, offset);
    offset = d.next;
    const iqmp = readBuffer(privateSection, offset);
    offset = iqmp.next;
    const p = readBuffer(privateSection, offset);
    offset = p.next;
    const q = readBuffer(privateSection, offset);
    const publicKeyBlob =
      envelope.publicSection.length > 0
        ? envelope.publicSection
        : concat(encodeString("ssh-rsa"), toSSHMPInt(e.value), toSSHMPInt(n.value));
    return importRsa({
      n: n.value,
      e: e.value,
      d: d.value,
      p: p.value,
      q: q.value,
      iqmp: iqmp.value,
      publicKeyBlob,
    });
  }

  if (keyType === "ecdsa-sha2-nistp256" || keyType === "ecdsa-sha2-nistp384" || keyType === "ecdsa-sha2-nistp521") {
    const curveName = readCString(privateSection, offset);
    offset = curveName.next;
    const point = readBuffer(privateSection, offset);
    offset = point.next;
    const d = readBuffer(privateSection, offset);
    const publicKeyBlob =
      envelope.publicSection.length > 0
        ? envelope.publicSection
        : concat(encodeString(keyType), encodeString(curveName.value), encodeString(point.value));
    return importEcdsa(keyType, d.value, point.value, publicKeyBlob);
  }

  throw new Error(
    `不支持的密钥类型: ${keyType}，当前支持 ssh-ed25519、ssh-rsa、ecdsa-sha2-nistp256/384/521`,
  );
}

function containsOid(data: Uint8Array, oid: number[]): boolean {
  outer: for (let i = 0; i <= data.length - oid.length; i++) {
    for (let j = 0; j < oid.length; j++) {
      if (data[i + j] !== oid[j]) continue outer;
    }
    return true;
  }
  return false;
}

function readDerLength(data: Uint8Array, offset: number): { length: number; next: number } {
  const first = data[offset];
  if ((first & 0x80) === 0) return { length: first, next: offset + 1 };
  const count = first & 0x7f;
  if (count === 0 || count > 4 || offset + 1 + count > data.length) {
    throw new Error("私钥格式损坏：DER 长度无效");
  }
  let length = 0;
  for (let i = 0; i < count; i++) {
    length = (length << 8) | data[offset + 1 + i];
  }
  return { length, next: offset + 1 + count };
}

function readDerInteger(data: Uint8Array, offset: number): { value: Uint8Array; next: number } {
  if (data[offset] !== 0x02) {
    throw new Error("私钥格式损坏：期望 INTEGER");
  }
  const len = readDerLength(data, offset + 1);
  const end = len.next + len.length;
  if (end > data.length) {
    throw new Error("私钥格式损坏：INTEGER 越界");
  }
  return { value: data.subarray(len.next, end), next: end };
}

function pkcs1ToJwk(der: Uint8Array): JsonWebKey {
  if (der[0] !== 0x30) {
    throw new Error("不支持的私钥格式，无法解析 PKCS#1 RSA 私钥");
  }
  const seq = readDerLength(der, 1);
  let offset = seq.next;
  const end = seq.next + seq.length;
  offset = readDerInteger(der, offset).next;

  const fields: Uint8Array[] = [];
  while (offset < end && fields.length < 8) {
    const field = readDerInteger(der, offset);
    fields.push(field.value);
    offset = field.next;
  }
  if (fields.length < 8) {
    throw new Error("私钥格式损坏：PKCS#1 RSA 字段不完整");
  }

  return {
    kty: "RSA",
    n: bytesToBase64Url(fields[0]),
    e: bytesToBase64Url(fields[1]),
    d: bytesToBase64Url(fields[2]),
    p: bytesToBase64Url(fields[3]),
    q: bytesToBase64Url(fields[4]),
    dp: bytesToBase64Url(fields[5]),
    dq: bytesToBase64Url(fields[6]),
    qi: bytesToBase64Url(fields[7]),
  };
}

async function signingKeyFromRsaJwk(jwk: JsonWebKey): Promise<SSHSigningKey> {
  const signingKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
    false,
    ["sign"],
  );
  const n = base64UrlToBytes(jwk.n ?? "");
  const e = base64UrlToBytes(jwk.e ?? "");
  return {
    algorithm: "rsa-sha2-512",
    publicKeyBlob: concat(encodeString("ssh-rsa"), toSSHMPInt(e), toSSHMPInt(n)),
    async sign(data) {
      const raw = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signingKey, data));
      return wrapSignature("rsa-sha2-512", raw);
    },
  };
}

async function parsePemSigningKey(pem: string): Promise<SSHSigningKey> {
  if (pem.includes("BEGIN ENCRYPTED PRIVATE KEY") || pem.includes("Proc-Type: 4,ENCRYPTED")) {
    throw new Error("暂不支持加密的 PKCS#1/PKCS#8 私钥，请改用 OpenSSH 格式私钥");
  }

  const der = pemToRaw(pem);

  if (pem.includes("BEGIN RSA PRIVATE KEY") || containsOid(der, OID_RSA)) {
    if (pem.includes("BEGIN RSA PRIVATE KEY")) {
      return signingKeyFromRsaJwk(pkcs1ToJwk(der));
    }
    const signingKey = await crypto.subtle.importKey(
      "pkcs8",
      der,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
      true,
      ["sign"],
    );
    return signingKeyFromRsaJwk(await exportJwk(signingKey));
  }

  if (containsOid(der, OID_ED25519)) {
    const signingKey = await crypto.subtle.importKey("pkcs8", der, { name: "Ed25519" }, true, ["sign"]);
    const jwk = await exportJwk(signingKey);
    const x = base64UrlToBytes(jwk.x ?? "");
    return {
      algorithm: "ssh-ed25519",
      publicKeyBlob: concat(encodeString("ssh-ed25519"), encodeString(x)),
      async sign(data) {
        const raw = new Uint8Array(await crypto.subtle.sign("Ed25519", signingKey, data));
        return wrapSignature("ssh-ed25519", raw);
      },
    };
  }

  if (containsOid(der, OID_EC)) {
    const webCurve = containsOid(der, OID_P256)
      ? "P-256"
      : containsOid(der, OID_P384)
        ? "P-384"
        : containsOid(der, OID_P521)
          ? "P-521"
          : null;
    if (!webCurve) {
      throw new Error("不支持的 EC 曲线，当前支持 nistp256/384/521");
    }
    const keyType =
      webCurve === "P-256"
        ? "ecdsa-sha2-nistp256"
        : webCurve === "P-384"
          ? "ecdsa-sha2-nistp384"
          : "ecdsa-sha2-nistp521";
    const signingKey = await crypto.subtle.importKey(
      "pkcs8",
      der,
      { name: "ECDSA", namedCurve: webCurve },
      true,
      ["sign"],
    );
    const jwk = await exportJwk(signingKey);
    const curve = ECDSA_CURVES[keyType];
    const x = padLeft(base64UrlToBytes(jwk.x ?? ""), curve.size);
    const y = padLeft(base64UrlToBytes(jwk.y ?? ""), curve.size);
    const point = new Uint8Array(1 + curve.size * 2);
    point[0] = 0x04;
    point.set(x, 1);
    point.set(y, 1 + curve.size);
    const curveName = keyType.slice("ecdsa-sha2-".length);
    return {
      algorithm: keyType,
      publicKeyBlob: concat(encodeString(keyType), encodeString(curveName), encodeString(point)),
      async sign(data) {
        const raw = new Uint8Array(
          await crypto.subtle.sign({ name: "ECDSA", hash: curve.hash }, signingKey, data),
        );
        const half = raw.length / 2;
        const sshSig = concat(toSSHMPInt(raw.subarray(0, half)), toSSHMPInt(raw.subarray(half)));
        return wrapSignature(keyType, sshSig);
      },
    };
  }

  throw new Error("不支持的私钥格式，请使用 OpenSSH、PKCS#8 或 PKCS#1 PEM 私钥");
}

export async function parsePrivateKey(pem: string, passphrase?: string): Promise<SSHSigningKey> {
  const trimmed = pem.replace(/\r\n/g, "\n").replace(/\r/g, "\n").trim();
  if (!trimmed) {
    throw new Error("私钥不能为空");
  }
  if (trimmed.includes("BEGIN OPENSSH PRIVATE KEY")) {
    return parseOpenSSHSigningKey(trimmed, passphrase);
  }
  if (
    trimmed.includes("BEGIN PRIVATE KEY") ||
    trimmed.includes("BEGIN RSA PRIVATE KEY") ||
    trimmed.includes("BEGIN EC PRIVATE KEY") ||
    trimmed.includes("BEGIN ENCRYPTED PRIVATE KEY")
  ) {
    return parsePemSigningKey(trimmed);
  }
  throw new Error("不支持的私钥格式，请使用 OpenSSH、PKCS#8 或 PKCS#1 PEM 私钥");
}
