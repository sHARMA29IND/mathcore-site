// Pages Function: POST /api/contact
//
// Receives the contact form and relays it to a small Worker
// (mathcore-contact-mail) that actually sends the email, because Cloudflare
// Pages Functions cannot hold a send_email binding (Workers-only) — see
// worker/mail-relay.js for the sending side and why this split exists.
//
// This does NOT touch the Bug Clinic engagement system directly (that still
// requires the owner to key in an engagement on the backend) — it is the
// "did my message actually reach the owner" layer that mailto: links can't
// guarantee, since not every browser/OS has a configured mail client.
//
// No credentials are exposed to the browser: the HMAC key used to sign the
// server-to-server call to the relay Worker lives only in this Function's
// environment variable, set via `wrangler pages secret put`, never shipped
// to client-side JavaScript.

const MAX_LEN = { name: 120, email: 200, message: 4000, company: 120 };
const RELAY_URL = "https://mathcore-contact-mail.saharsh-jani.workers.dev/relay";

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

export async function onRequestPost({ request, env }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ ok: false, error: "invalid request" }, { status: 400 });
  }

  const name = clean(body.name, MAX_LEN.name);
  const email = clean(body.email, MAX_LEN.email);
  const company = clean(body.company, MAX_LEN.company);
  const service = clean(body.service, 40);
  const message = clean(body.message, MAX_LEN.message);

  if (!name || !isEmail(email) || message.length < 10) {
    return Response.json(
      { ok: false, error: "please provide a valid name, email, and a short description" },
      { status: 400 }
    );
  }
  // Basic bot resistance: an unexpected honeypot field being filled means
  // it's very likely an automated submission, not a real client.
  if (body.website) {
    return Response.json({ ok: true }); // pretend success, drop silently
  }

  const text = [
    `New contact form submission from mathcore.dev`,
    ``,
    `Name: ${name}`,
    `Email: ${email}`,
    company ? `Company: ${company}` : null,
    service ? `Service of interest: ${service}` : null,
    ``,
    `Message:`,
    message,
  ].filter(Boolean).join("\n");

  const subject = `Contact form: ${name}${service ? " — " + service : ""}`;
  const relayBody = enc.encode(JSON.stringify({ subject, text, replyTo: email }));
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = toHex(crypto.getRandomValues(new Uint8Array(8)));
  const sig = await hmacHex(env.RELAY_HMAC_KEY,
    `POST\n/relay\n${ts}\n${nonce}\n${await sha256Hex(relayBody)}`);

  try {
    const res = await fetch(RELAY_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "mathcore-pages-function/1.0",
        "X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": sig,
      },
      body: relayBody,
    });
    if (!res.ok) throw new Error(`relay returned ${res.status}`);
  } catch (e) {
    return Response.json(
      { ok: false, error: "could not send right now — please email hello@mathcore.dev directly" },
      { status: 502 }
    );
  }
  return Response.json({ ok: true });
}

export async function onRequestGet() {
  return Response.json({ error: "use POST" }, { status: 405 });
}
