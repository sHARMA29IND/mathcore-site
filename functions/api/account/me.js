// GET /api/account/me — who is the current session, if any.
// Decrypts the stored email only for the owner of that session, to show it
// back to them (e.g. "signed in as ...") — never returned for anyone else.
import { sha256Hex, decryptEmail } from "../../_lib/crypto.js";

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.split(";").map((p) => p.trim()).find((p) => p.startsWith(name + "="));
  return match ? match.slice(name.length + 1) : null;
}

export async function onRequestGet({ request, env }) {
  if (!env.USERS_DB) return Response.json({ ok: false, authenticated: false }, { status: 503 });
  const token = getCookie(request, "mc_session");
  if (!token) return Response.json({ ok: true, authenticated: false });

  const tokenHash = await sha256Hex(token);
  const now = new Date().toISOString();
  const session = await env.USERS_DB.prepare(
    "SELECT user_id, expires_at FROM sessions WHERE token_hash = ?"
  ).bind(tokenHash).first();
  if (!session || session.expires_at < now) {
    return Response.json({ ok: true, authenticated: false });
  }
  const user = await env.USERS_DB.prepare(
    "SELECT email_encrypted, email_iv, verified, created_at FROM users WHERE id = ?"
  ).bind(session.user_id).first();
  if (!user) return Response.json({ ok: true, authenticated: false });

  const email = await decryptEmail(user.email_encrypted, user.email_iv, env.EMAIL_ENC_KEY);
  return Response.json({
    ok: true, authenticated: true, email, verified: !!user.verified, created_at: user.created_at,
  });
}
