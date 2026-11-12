// Shared crypto helpers for account storage.
//
// Three distinct primitives, each applied to the field it's actually
// correct for (not redundantly applied to the same data):
//
// 1. PASSWORD -> salted hash (PBKDF2-SHA256, 100,000 iterations, random
//    16-byte salt per user). One-way by design: we never need to recover
//    a password, only verify a re-submitted one matches.
//    NOTE: 100,000 is the Cloudflare Workers WebCrypto PBKDF2 ceiling
//    (requests above that throw NotSupportedError at runtime). OWASP's
//    current baseline recommendation for PBKDF2-SHA256 is 600,000+, but
//    the Workers runtime does not allow it. 100,000 is the platform max
//    we can use here.
// 2. EMAIL (for sending mail / display) -> AES-256-GCM ENCRYPTION with a
//    random 12-byte IV per record, under a server-held key. Reversible by
//    design: we must be able to decrypt it to actually send a verification
//    or login-related email.
// 3. EMAIL (for lookup at login time) -> a deterministic HMAC-SHA256
//    "lookup hash" under a separate key, so we can find a user's row by
//    the email they type in without storing plaintext email in a
//    searchable column, and without weakening the password hash's
//    one-wayness by reusing its salt scheme for something else.
//
// All three run on the Workers runtime's native WebCrypto (SubtleCrypto) —
// no third-party crypto library.
const enc = new TextEncoder();
const dec = new TextDecoder();

function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function toB64(buf) {
  let bin = "";
  for (const b of new Uint8Array(buf)) bin += String.fromCharCode(b);
  return btoa(bin);
}
function fromB64(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// --- 1. Password: PBKDF2-SHA256 salted hash ---------------------------------
// Capped at 100,000 — the Cloudflare Workers WebCrypto PBKDF2 ceiling.
const PBKDF2_ITERATIONS = 100000;

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt);
  return { hash: toHex(hash), salt: toHex(salt) };
}

export async function verifyPassword(password, saltHex, expectedHashHex) {
  const salt = fromHex(saltHex);
  const hash = toHex(await pbkdf2(password, salt));
  return timingSafeEqual(hash, expectedHashHex);
}

async function pbkdf2(password, salt) {
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial, 256
  );
}

// --- 2. Email: AES-256-GCM encryption ---------------------------------------
async function aesKey(keyHex) {
  const raw = fromHex(keyHex).slice(0, 32); // 32 bytes = AES-256
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function encryptEmail(email, keyHex) {
  const key = await aesKey(keyHex);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(email));
  return { ciphertext: toB64(ciphertext), iv: toB64(iv) };
}

export async function decryptEmail(ciphertextB64, ivB64, keyHex) {
  const key = await aesKey(keyHex);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(ivB64) }, key, fromB64(ciphertextB64)
  );
  return dec.decode(plaintext);
}

// --- 3. Email: deterministic HMAC lookup hash -------------------------------
export async function emailLookupHash(email, keyStr) {
  const key = await crypto.subtle.importKey("raw", enc.encode(keyStr), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(email.toLowerCase().trim()));
  return toHex(sig);
}

// --- misc: random tokens (session tokens, verification tokens) -------------
export function randomToken(bytes = 32) {
  return toHex(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function sha256Hex(text) {
  return toHex(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}
