// GET /api/account/verify?token=... — complete email verification.
//
// Ready to use the moment a real verification email can be sent to the
// user (pending the Email Service decision noted in signup.js). The token
// logic itself is fully functional today; only the "send it to the user"
// step is missing.
import { sha256Hex } from "../../_lib/crypto.js";

function page(message) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Verify — Mathcore</title>
<link rel="stylesheet" href="/css/style.css"></head><body>
<header class="site-header"><div class="wrap"><a class="brand" href="/">mathcore<span class="dot">.dev</span></a></div></header>
<main class="wrap page-section"><h1>Email verification</h1><p>${message}</p></main></body></html>`;
}

export async function onRequestGet({ request, env }) {
  const token = new URL(request.url).searchParams.get("token") || "";
  if (!token || !env.USERS_DB) {
    return new Response(page("Invalid or missing verification link."), { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } });
  }
  const tokenHash = await sha256Hex(token);
  const now = new Date().toISOString();
  const user = await env.USERS_DB.prepare(
    "SELECT id, verification_expires_at FROM users WHERE verification_token_hash = ? AND verified = 0"
  ).bind(tokenHash).first();
  if (!user || user.verification_expires_at < now) {
    return new Response(page("This verification link is invalid or has expired."), { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } });
  }
  await env.USERS_DB.prepare(
    "UPDATE users SET verified = 1, verification_token_hash = NULL, verified_at = ? WHERE id = ?"
  ).bind(new Date().toISOString(), user.id).run();
  return new Response(page("Your email has been verified. You can now log in."), { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
}
