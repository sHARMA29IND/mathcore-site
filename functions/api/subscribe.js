// Pages Function: POST /api/subscribe
//
// A real, compliant opt-in signup for occasional updates from Mathcore
// (new services, availability, relevant write-ups) — NOT a purchased or
// scraped list; only people who submit this form themselves.
//
// Compliance notes (read before changing this file):
// * SINGLE opt-in, not double opt-in. We cannot currently email the
//   subscriber a confirmation link (see worker/mail-relay.js for why —
//   the send_email binding can only deliver to one pinned owner address).
//   Single opt-in + an immediate, no-login unsubscribe link is compliant
//   under CAN-SPAM and is standard practice for a low-volume B2B update
//   list; it is disclosed as such on the signup form itself.
// * Every email we might send references this list and includes the
//   unsubscribe link below — unsubscribing takes effect immediately
//   (the record is deleted, not just flagged), with no login required.
// * We do not sell, rent, or share this list with any third party.
// * Honeypot + basic validation mirror functions/api/contact.js.
const MAX_LEN = { email: 200 };

function clean(s, max) {
  return String(s || "").replace(/[\r\n]+/g, " ").slice(0, max).trim();
}
function isEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) && s.length <= MAX_LEN.email;
}

const enc = new TextEncoder();
function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sha256Hex(bytes) {
  return toHex(await crypto.subtle.digest("SHA-256", bytes));
}
async function hmacHex(keyStr, message) {
  const key = await crypto.subtle.importKey("raw", enc.encode(keyStr), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toHex(await crypto.subtle.sign("HMAC", key, enc.encode(message)));
}

const RELAY_URL = "https://mathcore-contact-mail.saharsh-jani.workers.dev/notify";

async function notifyOwner(env, subject, text) {
  const body = enc.encode(JSON.stringify({ subject, text }));
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = toHex(crypto.getRandomValues(new Uint8Array(8)));
  const sig = await hmacHex(env.RELAY_HMAC_KEY, `POST\n/notify\n${ts}\n${nonce}\n${await sha256Hex(body)}`);
  await fetch(RELAY_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", "User-Agent": "mathcore-pages-function/1.0",
              "X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": sig },
    body,
  }).catch(() => {}); // best-effort notification; subscription itself still succeeds
}

export async function onRequestPost({ request, env }) {
  if (!env.RATE_LIMIT_KV) {
    return Response.json({ ok: false, error: "signup is temporarily unavailable" }, { status: 503 });
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ ok: false, error: "invalid request" }, { status: 400 });
  }
  const email = clean(body.email, MAX_LEN.email);
  if (!isEmail(email)) {
    return Response.json({ ok: false, error: "please provide a valid email address" }, { status: 400 });
  }
  if (body.website) {
    return Response.json({ ok: true }); // honeypot: pretend success, store nothing
  }

  // Each subscriber's unsubscribe token is an HMAC of their own email under
  // the same key used for server-to-server signing — deterministic, so the
  // unsubscribe link can be regenerated without storing a separate secret,
  // but not guessable without the key.
  const token = await hmacHex(env.RELAY_HMAC_KEY, `unsubscribe:${email.toLowerCase()}`);
  const key = `sub:${email.toLowerCase()}`;

  const existing = await env.RATE_LIMIT_KV.get(key);
  if (existing) {
    return Response.json({ ok: true, already: true });
  }
  await env.RATE_LIMIT_KV.put(key, JSON.stringify({
    email, subscribed_at: new Date().toISOString(), token,
  }));

  await notifyOwner(env, "New newsletter signup",
    `New signup for the Mathcore updates list:\n\nEmail: ${email}\nAt: ${new Date().toISOString()}`);

  return Response.json({ ok: true });
}

export async function onRequestGet() {
  return Response.json({ error: "use POST" }, { status: 405 });
}
