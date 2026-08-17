(function () {
  "use strict";
  var theme;
  try {
    theme = window.localStorage.getItem("configdeck.theme");
  } catch (_error) {
    theme = null;
  }
  if (theme !== "light" && theme !== "dark") {
    theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches
      ? "light"
      : "dark";
  }
  document.documentElement.dataset.theme = theme;
  var sidebarCollapsed = false;
  try {
    sidebarCollapsed = window.localStorage.getItem("configdeck.sidebarCollapsed") === "true";
  } catch (_error) {
    sidebarCollapsed = false;
  }
  document.documentElement.dataset.sidebar = sidebarCollapsed ? "collapsed" : "expanded";
}());
