// POST /api/account/login — verify credentials, issue a session.
//
// Looks the user up by the deterministic email lookup hash (never by
// decrypting every row's email), verifies the submitted password against
// the stored PBKDF2 hash, and on success issues a random session token
// whose SHA-256 hash (not the raw token) is stored server-side — so a
// leaked database still can't be used to forge a session.
import { emailLookupHash, verifyPassword, randomToken, sha256Hex } from "../../_lib/crypto.js";

const SESSION_TTL_SECONDS = 7 * 24 * 3600; // 7 days
const MAX_ATTEMPTS_PER_MINUTE = 5;

export async function onRequestPost({ request, env }) {
  if (!env.USERS_DB) {
    return Response.json({ ok: false, error: "login is temporarily unavailable" }, { status: 503 });
  }
  let body;
  try { body = await request.json(); } catch { return Response.json({ ok: false, error: "invalid request" }, { status: 400 }); }

  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!email || !password) {
    return Response.json({ ok: false, error: "email and password required" }, { status: 400 });
  }

  // Per-email login attempt throttling (separate from the site-wide per-IP
  // rate limiter in functions/_middleware.js) to resist password guessing.
  if (env.RATE_LIMIT_KV) {
    const throttleKey = `login_attempts:${email}:${Math.floor(Date.now() / 60000)}`;
    const attempts = parseInt((await env.RATE_LIMIT_KV.get(throttleKey)) || "0", 10);
    if (attempts >= MAX_ATTEMPTS_PER_MINUTE) {
      return Response.json({ ok: false, error: "too many attempts, please wait a minute" }, { status: 429 });
    }
    await env.RATE_LIMIT_KV.put(throttleKey, String(attempts + 1), { expirationTtl: 120 });
  }

  const lookupHash = await emailLookupHash(email, env.EMAIL_LOOKUP_KEY);
  const user = await env.USERS_DB.prepare(
    "SELECT id, password_hash, password_salt, verified FROM users WHERE email_lookup_hash = ?"
  ).bind(lookupHash).first();

  // Constant-shape response whether the account exists or the password is
  // wrong, so this endpoint doesn't reveal which emails have accounts.
  const genericError = () => Response.json({ ok: false, error: "incorrect email or password" }, { status: 401 });
  if (!user) {
    await verifyPassword(password, "00".repeat(16), "0"); // keep timing similar; discard result
    return genericError();
  }
  const valid = await verifyPassword(password, user.password_salt, user.password_hash);
  if (!valid) return genericError();

  const sessionToken = randomToken(32);
  const sessionTokenHash = await sha256Hex(sessionToken);
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_TTL_SECONDS * 1000).toISOString();
  await env.USERS_DB.prepare(
    "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)"
  ).bind(sessionTokenHash, user.id, now.toISOString(), expires).run();

  const cookie = `mc_session=${sessionToken}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_SECONDS}`;
  return new Response(JSON.stringify({ ok: true, verified: !!user.verified }), {
    status: 200,
    headers: { "Content-Type": "application/json", "Set-Cookie": cookie, "Cache-Control": "no-store" },
  });
}

export async function onRequestGet() {
  return Response.json({ error: "use POST" }, { status: 405 });
}
