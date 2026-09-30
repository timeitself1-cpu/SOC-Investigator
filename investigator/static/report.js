"use strict";
// Evidence navigation: client-side filtering over data attributes the server
// rendered (already HTML-escaped). No telemetry is ever inserted as HTML here.
(() => {
  const panel = document.getElementById("evidence-filters");
  if (!panel) return;
  const items = Array.from(document.querySelectorAll("details.evidence"));
  const q = document.getElementById("ev-q");
  const cat = document.getElementById("ev-cat");
  const host = document.getElementById("ev-host");
  const cited = document.getElementById("ev-cited");
  const flagged = document.getElementById("ev-flagged");
  const count = document.getElementById("ev-count");
  const expand = document.getElementById("ev-expand");

  function matches(el) {
    const text = (q.value || "").trim().toLowerCase();
    if (text && !el.dataset.text.includes(text)) return false;
    if (cat.value && el.dataset.category !== cat.value) return false;
    if (host.value && el.dataset.host !== host.value) return false;
    if (cited.checked && el.dataset.cited !== "yes") return false;
    if (flagged.checked && el.dataset.flagged !== "yes") return false;
    return true;
  }

  function apply() {
    let shown = 0;
    for (const el of items) {
      const ok = matches(el);
      el.hidden = !ok;
      if (ok) shown++;
    }
    count.textContent = `${shown} of ${items.length} shown`;
  }

  // Jumping to #EV-xxxx opens that item and clears filters that would hide it.
  function reveal() {
    const id = decodeURIComponent(location.hash.slice(1));
    const el = id ? document.getElementById(id) : null;
    if (el && el.classList.contains("evidence")) {
      if (el.hidden) {
        q.value = ""; cat.value = ""; host.value = ""; cited.checked = false; flagged.checked = false;
        apply();
      }
      el.open = true;
    }
  }

  for (const input of [q, cat, host, cited, flagged]) input.addEventListener("input", apply);
  expand.addEventListener("click", () => { for (const el of items) if (!el.hidden) el.open = true; });
  window.addEventListener("hashchange", reveal);
  panel.hidden = false;
  apply();
  reveal();
})();
