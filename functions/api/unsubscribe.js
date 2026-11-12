// Pages Function: GET /api/unsubscribe?email=...&token=...
//
// No login required, takes effect immediately by deleting the subscriber's
// record outright (not a soft "unsubscribed" flag) — see functions/api/subscribe.js
// for the compliance notes this pairs with.
const enc = new TextEncoder();
function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function hmacHex(keyStr, message) {
  const key = await crypto.subtle.importKey("raw", enc.encode(keyStr), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toHex(await crypto.subtle.sign("HMAC", key, enc.encode(message)));
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function page(message) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Unsubscribe — Mathcore</title>
<link rel="stylesheet" href="/css/style.css"></head><body>
<header class="site-header"><div class="wrap"><a class="brand" href="/">mathcore<span class="dot">.dev</span></a></div></header>
<main class="wrap page-section"><h1>Unsubscribe</h1><p>${message}</p></main></body></html>`;
}

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const email = (url.searchParams.get("email") || "").trim().toLowerCase();
  const token = url.searchParams.get("token") || "";
  if (!email || !token || !env.RATE_LIMIT_KV) {
    return new Response(page("Invalid or incomplete unsubscribe link."), { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } });
  }
  const expected = await hmacHex(env.RELAY_HMAC_KEY, `unsubscribe:${email}`);
  if (!timingSafeEqual(expected, token)) {
    return new Response(page("Invalid or expired unsubscribe link."), { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } });
  }
  await env.RATE_LIMIT_KV.delete(`sub:${email}`);
  return new Response(page(`You have been unsubscribed. ${email} will not receive any further updates from us.`),
    { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
}
