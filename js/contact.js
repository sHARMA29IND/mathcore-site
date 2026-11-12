// Contact form submission. First-party only, no third-party requests,
// no credentials of any kind handled client-side.
(function () {
  const form = document.getElementById("contact-form");
  const status = document.getElementById("form-status");
  if (!form) return;

  form.addEventListener("submit", async function (ev) {
    ev.preventDefault();
    status.textContent = "Sending…";
    status.className = "form-status";

    const data = {
      name: form.name.value,
      email: form.email.value,
      company: form.company.value,
      service: form.service.value,
      message: form.message.value,
      website: form.website.value, // honeypot
    };

    try {
      const res = await fetch("/api/contact", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      const out = await res.json().catch(() => ({}));
      if (res.ok && out.ok) {
        status.textContent = "Sent — we'll reply by email.";
        status.className = "form-status ok";
        form.reset();
      } else {
        status.textContent = out.error || "Could not send — please email hello@mathcore.dev directly.";
        status.className = "form-status err";
      }
    } catch {
      status.textContent = "Could not send — please email hello@mathcore.dev directly.";
      status.className = "form-status err";
    }
  });
})();
