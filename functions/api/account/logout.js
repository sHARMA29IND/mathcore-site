// POST /api/account/logout — revoke the current session immediately.
import { sha256Hex } from "../../_lib/crypto.js";

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.split(";").map((p) => p.trim()).find((p) => p.startsWith(name + "="));
  return match ? match.slice(name.length + 1) : null;
}

export async function onRequestPost({ request, env }) {
  const token = getCookie(request, "mc_session");
  if (token && env.USERS_DB) {
    const tokenHash = await sha256Hex(token);
    await env.USERS_DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
  }
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json",
              "Set-Cookie": "mc_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0" },
  });
}
