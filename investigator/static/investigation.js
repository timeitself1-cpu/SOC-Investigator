"use strict";
(() => {
  const feed = document.getElementById("activity");
  const runId = feed.dataset.runId;
  const connection = document.getElementById("connection");
  const kinds = new Set(["info", "tool", "model", "warning", "error", "done"]);
  let since = 0, errors = 0;

  function fail(message) {
    document.getElementById("spin").style.display = "none";
    document.getElementById("errmsg").textContent = message;
    document.getElementById("failed").style.display = "block";
  }

  async function poll() {
    try {
      const res = await fetch(`/api/run/${encodeURIComponent(runId)}?since=${since}`, {
        cache: "no-store", signal: AbortSignal.timeout(10000)
      });
      if (res.status === 404) {
        fail("This run is no longer available. Return to the queue to start a new investigation.");
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      connection.textContent = "";
      errors = 0;
      for (const a of data.activity) {
        const li = document.createElement("li");
        const dot = document.createElement("span");
        dot.className = `dot ${kinds.has(a.kind) ? a.kind : "info"}`;
        const text = document.createElement("div");
        const time = document.createElement("span");
        time.className = "mono small muted";
        time.textContent = String(a.at).slice(11, 19);
        text.append(time, document.createTextNode(` ${a.message}`));
        li.append(dot, text);
        feed.appendChild(li);
      }
      since = data.next_index;
      if (data.status === "completed") {
        document.getElementById("spin").style.display = "none";
        document.getElementById("done").style.display = "block";
        const note = data.report_status === "completed" ? "Assessment ready for analyst review."
          : `Assessment ${data.report_status || "incomplete"}; inspect the limitations and audit trace.`;
        document.getElementById("reportstatus").textContent = note +
          (data.persistence_error ? " Report could not be saved to disk. Export it before closing this session." : "");
        return;
      }
      if (data.status === "error") {
        fail(data.error || "Investigation failed.");
        return;
      }
    } catch (err) {
      errors++;
      connection.textContent = "Connection interrupted; retrying…";
    }
    setTimeout(poll, Math.min(10000, 600 * (2 ** Math.min(errors, 4))));
  }
  poll();
})();
