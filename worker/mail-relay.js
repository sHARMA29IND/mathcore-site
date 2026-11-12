// mathcore-contact-mail — tiny Worker whose only job is sending the contact
// form email, because Pages Functions cannot hold a send_email binding
// (Workers-only limitation; see Cloudflare docs/community threads).
//
// Called ONLY by the Pages Function at /api/contact via an HMAC-signed
// server-to-server request (same scheme as business_os/server/signing.py),
// never directly from the browser. It can email exactly one address — the
// send_email binding is pinned to the owner's destination.
const enc = new TextEncoder();
const MAX_SKEW_S = 60;

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
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function verify(key, method, path, bodyBytes, headers, nowS) {
  const ts = headers.get("X-Timestamp") || "", nonce = headers.get("X-Nonce") || "", sig = headers.get("X-Signature") || "";
  if (!/^\d+$/.test(ts) || !/^[A-Za-z0-9]{8,64}$/.test(nonce) || !sig) return false;
  if (Math.abs(nowS - parseInt(ts, 10)) > MAX_SKEW_S) return false;
  const msg = `${method.toUpperCase()}\n${path}\n${ts}\n${nonce}\n${await sha256Hex(bodyBytes)}`;
  const expected = await hmacHex(key, msg);
  return timingSafeEqual(expected, sig);
}

function b64Lines(text) {
  const bytes = enc.encode(text);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/(.{76})/g, "$1\r\n");
}
const clean = (s) => String(s).replace(/[\r\n]/g, " ").slice(0, 4000);

export default {
  async fetch(request, env) {
    if (request.method !== "POST" || new URL(request.url).pathname !== "/relay") {
      return new Response("not found", { status: 404 });
    }
    const bodyBytes = new Uint8Array(await request.arrayBuffer());
    if (bodyBytes.length > 20000) return new Response("too large", { status: 413 });
    const ok = await verify(env.HMAC_KEY, "POST", "/relay", bodyBytes, request.headers, Math.floor(Date.now() / 1000));
    if (!ok) return new Response("unauthorized", { status: 401 });

    let doc;
    try { doc = JSON.parse(new TextDecoder().decode(bodyBytes)); } catch { return new Response("bad json", { status: 400 }); }
    const { subject, text, replyTo } = doc;
    if (typeof subject !== "string" || typeof text !== "string") {
      return new Response("missing fields", { status: 400 });
    }

    const nonce = toHex(crypto.getRandomValues(new Uint8Array(8)));
    const raw = [
      `From: Mathcore Contact Form <${env.MAIL_FROM}>`,
      `To: ${env.OWNER_EMAIL}`,
      replyTo ? `Reply-To: ${clean(replyTo).slice(0, 200)}` : null,
      `Subject: ${clean(subject).slice(0, 200)}`,
      `Date: ${new Date().toUTCString()}`,
      `Message-ID: <${nonce}@mathcore.dev>`,
      `MIME-Version: 1.0`,
      `Content-Type: text/plain; charset=utf-8`,
      `Content-Transfer-Encoding: base64`,
      ``,
      b64Lines(text),
    ].filter(Boolean).join("\r\n");

    try {
      const { EmailMessage } = await import("cloudflare:email");
      await env.EMAIL.send(new EmailMessage(env.MAIL_FROM, env.OWNER_EMAIL, raw));
    } catch (e) {
      return new Response(JSON.stringify({ sent: false, detail: String(e && e.message || e) }), { status: 502 });
    }
    return new Response(JSON.stringify({ sent: true }), { status: 200, headers: { "Content-Type": "application/json" } });
  },
};
