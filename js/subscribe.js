// Newsletter signup. First-party only; see functions/api/subscribe.js for
// the compliance notes (single opt-in, immediate no-login unsubscribe).
(function () {
  const form = document.getElementById("subscribe-form");
  const status = document.getElementById("subscribe-status");
  if (!form) return;

  form.addEventListener("submit", async function (ev) {
    ev.preventDefault();
    status.textContent = "Submitting…";
    status.className = "form-status";

    const data = { email: form.email.value, website: form.website.value };

    try {
      const res = await fetch("/api/subscribe", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      const out = await res.json().catch(() => ({}));
      if (res.ok && out.ok) {
        status.textContent = out.already
          ? "You're already on the list."
          : "Subscribed. You can unsubscribe at any time from the link in any email we send.";
        status.className = "form-status ok";
        form.reset();
      } else {
        status.textContent = out.error || "Could not subscribe right now.";
        status.className = "form-status err";
      }
    } catch {
      status.textContent = "Could not subscribe right now.";
      status.className = "form-status err";
    }
  });
})();
