(function () {
  function apply(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }

  function toggle() {
    var current = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
    apply(current === "dark" ? "light" : "dark");
  }

  window.__theme = { apply: apply, toggle: toggle };
})();
