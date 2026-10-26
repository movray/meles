// Loaded in <head> without defer: applies the chosen theme before the page
// is painted, so it does not flash in the system's colors first. The choice
// stays in this browser; without it the page follows the system.
(function () {
  "use strict";
  try {
    var t = localStorage.getItem("meles-theme");
    if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
  } catch (e) {}
})();
