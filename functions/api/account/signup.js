// POST /api/account/signup — create an account.
//
// Email is stored ENCRYPTED (AES-256-GCM, random IV) so it can later be
// decrypted to send mail; a separate deterministic HMAC "lookup hash" lets
// us find the row by email without a plaintext/searchable email column.
// Password is stored as a PBKDF2 hash with a random salt — never
// recoverable, only verifiable. See functions/_lib/crypto.js.
//
// Verified-email status: this account is created as unverified
// (verified = 0). Completing real email verification requires sending a
// confirmation link to the user's own address, which needs Cloudflare
// Email Service with a sending domain onboarded (not yet enabled — see
// SECURITY_LIMITATIONS.md / ai.json; pending an explicit owner decision on
// plan/provider). Until then, a verification token IS generated and
// stored (hashed), so verification can be completed as soon as sending is
// available, without re-architecting this endpoint.
import { hashPassword, emailLookupHash, encryptEmail, randomToken, sha256Hex } from "../../_lib/crypto.js";

const MAX_LEN = { email: 200, password: 200 };

function isEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) && s.length <= MAX_LEN.email;
}

export async function onRequestPost({ request, env }) {
  if (!env.USERS_DB) {
    return Response.json({ ok: false, error: "signup is temporarily unavailable" }, { status: 503 });
  }
  let body;
  try { body = await request.json(); } catch { return Response.json({ ok: false, error: "invalid request" }, { status: 400 }); }

  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!isEmail(email)) {
    return Response.json({ ok: false, error: "please provide a valid email address" }, { status: 400 });
  }
  if (password.length < 10 || password.length > MAX_LEN.password) {
    return Response.json({ ok: false, error: "password must be 10-200 characters" }, { status: 400 });
  }
  if (body.website) {
    return Response.json({ ok: true }); // honeypot
  }

  const lookupHash = await emailLookupHash(email, env.EMAIL_LOOKUP_KEY);
  const existing = await env.USERS_DB.prepare("SELECT id FROM users WHERE email_lookup_hash = ?")
    .bind(lookupHash).first();
  if (existing) {
    return Response.json({ ok: false, error: "an account with this email already exists" }, { status: 409 });
  }

  const { ciphertext, iv } = await encryptEmail(email, env.EMAIL_ENC_KEY);
  const { hash, salt } = await hashPassword(password);
  const id = randomToken(16);
  const verificationToken = randomToken(32);
  const verificationTokenHash = await sha256Hex(verificationToken);
  const now = new Date();
  const expires = new Date(now.getTime() + 24 * 3600 * 1000).toISOString();

  await env.USERS_DB.prepare(
    `INSERT INTO users (id, email_lookup_hash, email_encrypted, email_iv, password_hash,
       password_salt, verified, verification_token_hash, verification_expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`
  ).bind(id, lookupHash, ciphertext, iv, hash, salt, verificationTokenHash, expires, now.toISOString()).run();

  // NOTE: the verification email itself is not yet sendable to the user's own
  // address (see module docstring). The token above is ready to use the
  // moment that capability exists; nothing else about signup needs to change.
  return Response.json({
    ok: true,
    verified: false,
    note: "Account created. Email verification is not yet available on this deployment; your account is active but unverified.",
  });
}

export async function onRequestGet() {
  return Response.json({ error: "use POST" }, { status: 405 });
}
