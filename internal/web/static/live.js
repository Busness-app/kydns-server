// Refreshes the health badges and the lease table without a full page reload.
// Deliberately tiny: two timers and one fetch, no framework.
(function () {
  const HEALTH_MS = 10000;
  const LEASE_MS = 30000;

  let healthTimer = null;

  async function refreshHealth() {
    try {
      const resp = await fetch("/services/health.json", { headers: { Accept: "application/json" } });
      // A signed-out session will not sign itself back in. Stop polling and let
      // the next click land on the login page.
      if (resp.status === 401) {
        clearInterval(healthTimer);
        return;
      }
      if (!resp.ok) return; // a failed poll is not worth disturbing the page over
      const data = await resp.json();
      for (const s of data.health || []) {
        const cell = document.querySelector('[data-health-for="' + s.service_id + '"]');
        if (!cell) continue;
        cell.textContent = s.state;
        cell.className =
          "badge " + (s.state === "down" ? "down" : s.state === "up" ? "accent" : "");
      }
    } catch (e) {
      /* transient: the next tick tries again */
    }
  }

  if (document.querySelector("[data-health-for]")) {
    refreshHealth();
    healthTimer = setInterval(refreshHealth, HEALTH_MS);
  }
  if (document.getElementById("lease-table")) {
    setInterval(function () { location.reload(); }, LEASE_MS);
  }
})();
