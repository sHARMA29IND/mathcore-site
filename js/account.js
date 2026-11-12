(function () {
  const loggedOut = document.getElementById("logged-out");
  const loggedIn = document.getElementById("logged-in");
  const meInfo = document.getElementById("me-info");
  const signupForm = document.getElementById("signup-form");
  const loginForm = document.getElementById("login-form");
  const logoutBtn = document.getElementById("logout-btn");

  async function refresh() {
    const res = await fetch("/api/account/me");
    const out = await res.json().catch(() => ({ authenticated: false }));
    if (out.authenticated) {
      loggedOut.style.display = "none";
      loggedIn.style.display = "block";
      meInfo.textContent = `Signed in as ${out.email}${out.verified ? "" : " (unverified)"}. Account created ${new Date(out.created_at).toLocaleDateString()}.`;
    } else {
      loggedOut.style.display = "block";
      loggedIn.style.display = "none";
    }
  }

  signupForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const status = document.getElementById("signup-status");
    status.textContent = "Creating account…"; status.className = "form-status";
    const data = { email: signupForm.email.value, password: signupForm.password.value, website: signupForm.website.value };
    try {
      const res = await fetch("/api/account/signup", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
      const out = await res.json().catch(() => ({}));
      if (res.ok && out.ok) {
        status.textContent = out.note || "Account created.";
        status.className = "form-status ok";
        signupForm.reset();
      } else {
        status.textContent = out.error || "Could not create account.";
        status.className = "form-status err";
      }
    } catch { status.textContent = "Could not create account."; status.className = "form-status err"; }
  });

  loginForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const status = document.getElementById("login-status");
    status.textContent = "Logging in…"; status.className = "form-status";
    const data = { email: loginForm.email.value, password: loginForm.password.value };
    try {
      const res = await fetch("/api/account/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
      const out = await res.json().catch(() => ({}));
      if (res.ok && out.ok) {
        status.textContent = ""; loginForm.reset();
        refresh();
      } else {
        status.textContent = out.error || "Could not log in.";
        status.className = "form-status err";
      }
    } catch { status.textContent = "Could not log in."; status.className = "form-status err"; }
  });

  logoutBtn.addEventListener("click", async () => {
    await fetch("/api/account/logout", { method: "POST" });
    refresh();
  });

  refresh();
})();
