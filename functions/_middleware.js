// Site-wide middleware: rate-limits automated/crawler traffic.
//
// Rule (per the owner's instruction): up to 20 requests per minute PER USER
// are served immediately; requests above that limit for that same user are
// made to WAIT (briefly delayed, then served) rather than hard-blocked, so
// a well-behaved crawler that briefly bursts isn't locked out — only
// slowed. "Per user" here means per client IP address (CF-Connecting-IP):
// this is a public, unauthenticated static site with no login/account
// system, so IP is the only available identity signal, and is the
// standard practical definition of "per user" for anonymous web traffic.
//
// Implementation notes / honest limitations:
// * Counted per client IP (CF-Connecting-IP) in a 60-second fixed window
//   (not a precise sliding window) stored in Cloudflare KV. A fixed window
//   is simpler and uses far fewer KV writes than a true sliding log, which
//   matters because Workers KV has its own per-key write-rate ceiling on
//   the free plan; a fixed window is the correct trade-off here, not an
//   oversight.
// * "Wait" is implemented as an in-request delay (capped, see MAX_DELAY_MS)
//   proportional to how far over the limit the client is, then the request
//   proceeds normally. This is NOT a queue across requests (Workers/Pages
//   Functions don't support that) — each over-limit request independently
//   waits before being served.
// * KV is eventually consistent, so this is a best-effort limiter, not a
//   hard security boundary. It is a politeness/cost-control measure, not a
//   substitute for Cloudflare's own DDoS protection (which still applies
//   underneath, unconditionally, on every Cloudflare zone).
// * This file runs for EVERY request to the site (static pages included),
//   because Pages Functions middleware intercepts the whole route tree.
const LIMIT_PER_MINUTE = 20;
const MAX_DELAY_MS = 4000;      // never make a caller wait more than 4s
const DELAY_PER_OVERAGE_MS = 150;

function clientKey(request) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const window = Math.floor(Date.now() / 60000); // 60s fixed window id
  return `rl:${ip}:${window}`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function onRequest({ request, next, env }) {
  // No KV bound (e.g. local preview without the binding configured): fail
  // open rather than breaking the whole site over a rate-limit feature.
  if (!env.RATE_LIMIT_KV) {
    const response = await next();
    const headers = new Headers(response.headers);
    headers.set("X-RateLimit-Debug", "no-kv-binding");
    return new Response(response.body, { status: response.status, headers });
  }

  const key = clientKey(request);
  let count = 0;
  try {
    const raw = await env.RATE_LIMIT_KV.get(key);
    count = raw ? parseInt(raw, 10) || 0 : 0;
  } catch {
    return next(); // KV unavailable: fail open, don't take the site down
  }

  const newCount = count + 1;
  try {
    // expirationTtl cleans the key up automatically; no manual sweeping needed.
    await env.RATE_LIMIT_KV.put(key, String(newCount), { expirationTtl: 120 });
  } catch {
    // Write failed (e.g. KV's own rate limit) — proceed without delaying;
    // failing open is safer than failing the whole site closed.
    return next();
  }

  if (newCount > LIMIT_PER_MINUTE) {
    const overage = newCount - LIMIT_PER_MINUTE;
    const delay = Math.min(overage * DELAY_PER_OVERAGE_MS, MAX_DELAY_MS);
    await sleep(delay);
  }

  const response = await next();
  const headers = new Headers(response.headers);
  headers.set("X-RateLimit-Limit", String(LIMIT_PER_MINUTE));
  headers.set("X-RateLimit-Remaining", String(Math.max(LIMIT_PER_MINUTE - newCount, 0)));
  return new Response(response.body, { status: response.status, headers });
}
