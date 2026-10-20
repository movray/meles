// Progressive enhancement only: every page works without JavaScript.
(function () {
  "use strict";

  // Schedule chips fill the related input.
  document.querySelectorAll(".chips[data-fill]").forEach(function (group) {
    var input = document.getElementById(group.dataset.fill);
    if (!input) return;
    group.addEventListener("click", function (e) {
      var chip = e.target.closest(".chip");
      if (!chip) return;
      input.value = chip.dataset.value;
      input.focus();
    });
  });

  // Forms with data-confirm ask before submitting.
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (!window.confirm(form.dataset.confirm)) e.preventDefault();
    });
  });

  // Chart tooltips: one per column, positioned over the hovered column.
  document.querySelectorAll("[data-tooltip-host]").forEach(function (host) {
    var tip = host.querySelector(".tooltip");
    if (!tip) return;
    function show(target) {
      var box = target.getBoundingClientRect();
      var hostBox = host.getBoundingClientRect();
      tip.textContent = target.dataset.tip;
      tip.hidden = false;
      var x = box.left + box.width / 2 - hostBox.left;
      var half = tip.offsetWidth / 2;
      x = Math.max(half, Math.min(hostBox.width - half, x));
      tip.style.left = x + "px";
      tip.style.top = Math.max(0, box.top - hostBox.top + 12) + "px";
    }
    host.addEventListener("mouseover", function (e) {
      var t = e.target.closest(".hit");
      if (t) show(t);
    });
    host.addEventListener("mouseleave", function () { tip.hidden = true; });
    host.querySelectorAll(".hit").forEach(function (h) {
      h.setAttribute("tabindex", "0");
      h.addEventListener("focus", function () { show(h); });
      h.addEventListener("blur", function () { tip.hidden = true; });
    });
  });
})();
