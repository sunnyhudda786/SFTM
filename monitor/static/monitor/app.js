(function () {
  const loader = document.getElementById("slowLoader");
  const progress = document.getElementById("pageProgress");
  let hideTimer = null;

  function showLoader(label) {
    if (hideTimer) clearTimeout(hideTimer);
    if (progress) progress.classList.add("active");
    if (!loader) return;
    if (label) {
      const heading = loader.querySelector("h2");
      if (heading) heading.textContent = label;
    }
    loader.classList.add("visible");
    loader.setAttribute("aria-hidden", "false");
  }

  function hideLoader() {
    if (progress) progress.classList.remove("active");
    if (!loader) return;
    hideTimer = setTimeout(function () {
      loader.classList.remove("visible");
      loader.setAttribute("aria-hidden", "true");
    }, 180);
  }

  function shouldSkipLoader(link) {
    if (!link) return true;
    const href = link.getAttribute("href") || "";
    if (link.dataset.noLoader === "true") return true;
    if (link.target === "_blank") return true;
    if (href.startsWith("#") || href.startsWith("javascript:") || href.startsWith("mailto:")) return true;
    if (href.includes("/export/") || href.includes("/download/")) return true;
    try {
      return new URL(link.href).origin !== window.location.origin;
    } catch (e) {
      return true;
    }
  }

  function markActiveNav() {
    const path = window.location.pathname.replace(/\/$/, "") || "/";
    document.querySelectorAll(".nav a").forEach(function (link) {
      try {
        const linkPath = new URL(link.href).pathname.replace(/\/$/, "") || "/";
        if (linkPath === path || (linkPath !== "/" && path.startsWith(linkPath))) {
          link.classList.add("active");
        }
      } catch (e) {}
    });
  }

  function revealElements() {
    const items = document.querySelectorAll(".panel, .metric-card, .kpi-panel, .case-focus-card, .alert-card, .summary-tile, .visual-card, .notice-panel, .ops-hero, .simple-alert-hero");
    if (!("IntersectionObserver" in window)) {
      items.forEach(el => el.classList.add("reveal-visible"));
      return;
    }
    const observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("reveal-visible");
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.08 });
    items.forEach(function (el, index) {
      el.classList.add("reveal-item");
      el.style.setProperty("--reveal-delay", Math.min(index * 18, 220) + "ms");
      observer.observe(el);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.body.classList.add("dom-ready");
    markActiveNav();
    revealElements();
    showLoader(document.body.classList.contains("login-split-body") ? "Opening login" : "Loading workspace");
    setTimeout(hideLoader, 420);
  });

  window.addEventListener("load", hideLoader);
  window.addEventListener("pageshow", hideLoader);

  document.addEventListener("click", function (event) {
    const link = event.target.closest("a");
    if (shouldSkipLoader(link)) return;
    showLoader("Loading workspace");
  });

  document.addEventListener("submit", function (event) {
    const form = event.target;
    if (form && form.dataset.noLoader === "true") return;
    showLoader(document.body.classList.contains("login-split-body") ? "Signing in" : "Saving changes");
  });
})();
