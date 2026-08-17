(function () {
"use strict";

function currentTheme() {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

function updateThemeControls() {
  const isDark = currentTheme() === "dark";
  document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
    button.setAttribute("aria-pressed", String(isDark));
    button.setAttribute("aria-label", isDark ? "Switch to light theme" : "Switch to dark theme");
  });
  document.querySelectorAll("[data-theme-label]").forEach((label) => {
    label.textContent = isDark ? "Dark theme" : "Light theme";
  });
}

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  try {
    window.localStorage.setItem("configdeck.theme", theme);
  } catch (_error) {
    // The selected theme still applies for this page when storage is unavailable.
  }
  updateThemeControls();
}

function setSidebarCollapsed(collapsed, persist) {
  document.documentElement.dataset.sidebar = collapsed ? "collapsed" : "expanded";
  document.querySelectorAll("[data-sidebar-toggle]").forEach((button) => {
    button.setAttribute("aria-expanded", String(!collapsed));
    button.setAttribute("aria-label", collapsed ? "Expand sidebar" : "Collapse sidebar");
    button.setAttribute("title", collapsed ? "Expand sidebar" : "Collapse sidebar");
  });
  if (!persist) return;
  try {
    window.localStorage.setItem("configdeck.sidebarCollapsed", String(collapsed));
  } catch (_error) {
    // The selected sidebar state still applies for this page when storage is unavailable.
  }
}

function initializeApplicationShell() {
  setSidebarCollapsed(document.documentElement.dataset.sidebar === "collapsed", false);
  const breadcrumb = document.querySelector(".content-wrap > .breadcrumbs");
  const target = document.querySelector("[data-context-breadcrumbs]");
  if (breadcrumb && target) {
    breadcrumb.classList.add("topbar-breadcrumbs");
    target.replaceChildren(breadcrumb);
  }
}

function valueControl(type, value, name = "value_0") {
  let control;
  if (type === "boolean") {
    control = document.createElement("select");
    const placeholder = new Option("Choose true or false", "", !["true", "false"].includes(value), !["true", "false"].includes(value));
    placeholder.disabled = true;
    control.add(placeholder);
    control.add(new Option("true", "true", value === "true", value === "true"));
    control.add(new Option("false", "false", value === "false", value === "false"));
    control.required = true;
  } else if (type === "multiline") {
    control = document.createElement("textarea");
    control.rows = 3;
    control.maxLength = 32768;
    control.value = value;
  } else {
    control = document.createElement("input");
    control.type = type === "integer" ? "number" : type === "url" ? "url" : "text";
    if (type === "integer") control.step = "1";
    if (type !== "integer") control.maxLength = 32768;
    control.value = value;
    control.required = type === "integer" || type === "url";
  }
  control.name = name;
  control.dataset.valueInput = "";
  return control;
}

function updateValueSource(select) {
  const form = select.closest("form");
  const field = form?.querySelector(".comparison-value-field");
  if (!field) return;
  const operatorProvides = select.value === "OPERATOR_PROVIDED";
  field.hidden = operatorProvides;
  const hint = field.querySelector("[data-value-hint]");
  if (hint) hint.textContent = operatorProvides
    ? "The operator will provide this value securely during review."
    : "Restricted values are write-only here.";
}

function initializeValueSources() {
  document.querySelectorAll("[data-value-source]").forEach(updateValueSource);
}

let openSelectMenu;
const customSelectInstances = new WeakMap();

function closeCustomSelect() {
  if (!openSelectMenu) return;
  openSelectMenu.menu.hidden = true;
  openSelectMenu.trigger.setAttribute("aria-expanded", "false");
  openSelectMenu = undefined;
}

function positionCustomSelect(trigger, menu) {
  const rect = trigger.getBoundingClientRect();
  menu.style.width = `${rect.width}px`;
  menu.style.left = `${Math.max(8, Math.min(rect.left, window.innerWidth - rect.width - 8))}px`;
  menu.hidden = false;
  const menuHeight = menu.offsetHeight;
  const below = window.innerHeight - rect.bottom;
  menu.style.top = below >= Math.min(menuHeight + 6, 240)
    ? `${rect.bottom + 4}px`
    : `${Math.max(8, rect.top - menuHeight - 4)}px`;
}

function enhanceComparisonSelect(select) {
  if (select.dataset.customSelectReady !== undefined) return;
  select.dataset.customSelectReady = "";
  select.classList.add("native-select-hidden");
  select.setAttribute("aria-hidden", "true");
  select.tabIndex = -1;

  const trigger = document.createElement("button");
  trigger.type = "button";
  trigger.className = "custom-select-trigger";
  trigger.setAttribute("aria-haspopup", "listbox");
  trigger.setAttribute("aria-expanded", "false");
  const label = document.createElement("span");
  const arrow = document.createElement("span");
  arrow.className = "custom-select-arrow";
  arrow.textContent = "⌄";
  trigger.append(label, arrow);
  select.insertAdjacentElement("afterend", trigger);

  const menu = document.createElement("div");
  menu.className = "custom-select-menu";
  menu.setAttribute("role", "listbox");
  menu.hidden = true;
  document.body.append(menu);

  const sync = () => {
    const selected = select.options[select.selectedIndex];
    label.textContent = selected?.textContent || "Select";
    menu.replaceChildren();
    Array.from(select.options).forEach((option) => {
      const item = document.createElement("button");
      item.type = "button";
      item.className = "custom-select-option";
      item.textContent = option.textContent;
      item.disabled = option.disabled;
      item.setAttribute("role", "option");
      item.setAttribute("aria-selected", String(option.selected));
      if (option.selected) item.classList.add("is-selected");
      item.addEventListener("click", () => {
        select.value = option.value;
        select.dispatchEvent(new Event("change", { bubbles: true }));
        sync();
        closeCustomSelect();
        trigger.focus();
      });
      menu.append(item);
    });
  };

  const open = () => {
    closeCustomSelect();
    sync();
    positionCustomSelect(trigger, menu);
    trigger.setAttribute("aria-expanded", "true");
    openSelectMenu = { trigger, menu };
  };
  trigger.addEventListener("click", () => {
    if (openSelectMenu?.trigger === trigger) closeCustomSelect();
    else open();
  });
  trigger.addEventListener("keydown", (event) => {
    if (["ArrowDown", "ArrowUp", "Enter", " "].includes(event.key)) {
      event.preventDefault();
      open();
      const options = Array.from(menu.querySelectorAll(".custom-select-option:not(:disabled)"));
      (options.find((option) => option.classList.contains("is-selected")) || options[0])?.focus();
    } else if (event.key === "Escape") {
      closeCustomSelect();
    }
  });
  menu.addEventListener("keydown", (event) => {
    const options = Array.from(menu.querySelectorAll(".custom-select-option:not(:disabled)"));
    const index = options.indexOf(document.activeElement);
    if (event.key === "Escape") {
      closeCustomSelect();
      trigger.focus();
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const offset = event.key === "ArrowDown" ? 1 : -1;
      options[(index + offset + options.length) % options.length]?.focus();
    }
  });
  select.addEventListener("change", sync);
  customSelectInstances.set(select, { trigger, menu });
  sync();
}

function initializeCustomSelects(root = document) {
  root.querySelectorAll(".comparison-landscape-form select").forEach(enhanceComparisonSelect);
}

async function writeClipboard(text, status) {
  try {
    await navigator.clipboard.writeText(text);
    status.textContent = "Copied to clipboard.";
  } catch (_error) {
    status.textContent = "Clipboard permission was denied. Select and copy manually.";
  }
}

function setServiceView(view, persist) {
  const catalog = document.querySelector("[data-service-catalog]");
  if (!catalog || !["grid", "list"].includes(view)) return;
  catalog.dataset.view = view;
  document.querySelectorAll("[data-service-view]").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.serviceView === view));
  });
  if (!persist) return;
  try {
    window.localStorage.setItem("configdeck.serviceView", view);
  } catch (_error) {
    // The selected view still applies for this page when storage is unavailable.
  }
}

function updateServiceCatalog() {
  const catalog = document.querySelector("[data-service-catalog]");
  if (!catalog) return;
  const cards = Array.from(catalog.querySelectorAll("[data-service-card]"));
  const query = document.querySelector("[data-service-search]")?.value.trim().toLowerCase() || "";
  const sort = document.querySelector("[data-service-sort]")?.value || "updated";
  const status = document.querySelector("[data-service-status]")?.value || "active";
  const compare = (left, right) => {
    const archived = Number(left.dataset.serviceArchived) - Number(right.dataset.serviceArchived);
    if (archived !== 0) return archived;
    if (sort === "name-desc") return right.dataset.serviceName.localeCompare(left.dataset.serviceName);
    if (sort === "environments") {
      const environmentDifference = Number(right.dataset.serviceEnvironments) - Number(left.dataset.serviceEnvironments);
      if (environmentDifference !== 0) return environmentDifference;
    }
    if (sort === "updated") {
      const updatedDifference = right.dataset.serviceUpdated.localeCompare(left.dataset.serviceUpdated);
      if (updatedDifference !== 0) return updatedDifference;
    }
    return left.dataset.serviceName.localeCompare(right.dataset.serviceName);
  };
  const empty = catalog.querySelector("[data-service-empty]");
  cards.sort(compare).forEach((card) => catalog.insertBefore(card, empty));
  let visible = 0;
  cards.forEach((card) => {
    const searchable = `${card.dataset.serviceName} ${card.dataset.serviceDescription}`.toLowerCase();
    const lifecycleMatches = status === "all"
      || (status === "archived" && card.dataset.serviceArchived === "1")
      || (status === "active" && card.dataset.serviceArchived === "0");
    const matches = lifecycleMatches && (!query || searchable.includes(query));
    card.hidden = !matches;
    if (matches) visible += 1;
  });
  if (empty) empty.hidden = visible !== 0;
  const count = document.querySelector("[data-service-count]");
  if (count) count.textContent = `${visible} of ${cards.length} app${cards.length === 1 ? "" : "s"}`;
}

function initializeServiceCatalog() {
  if (!document.querySelector("[data-service-catalog]")) return;
  let view = "grid";
  try {
    const stored = window.localStorage.getItem("configdeck.serviceView");
    if (["grid", "list"].includes(stored)) view = stored;
  } catch (_error) {
    // Grid remains the safe default when storage is unavailable.
  }
  setServiceView(view, false);
  updateServiceCatalog();
}

function setComparisonExpanded(row, expanded) {
  const button = row.querySelector("[data-comparison-toggle]");
  const detail = button ? document.getElementById(button.dataset.comparisonToggle) : null;
  if (!button || !detail) return;
  button.setAttribute("aria-expanded", String(expanded));
  row.classList.toggle("is-expanded", expanded);
  detail.hidden = !expanded;
}

function updateEnvironmentSelection(changedToggle) {
  const root = document.querySelector("[data-environment-selector]");
  if (!root) return;
  const toggles = Array.from(root.querySelectorAll("[data-environment-toggle]"));
  const allToggle = root.querySelector("[data-environment-toggle-all]");
  if (toggles.length === 0) return;
  if (!toggles.some((toggle) => toggle.checked)) {
    (changedToggle || toggles[0]).checked = true;
  }
  const selected = new Set(toggles.filter((toggle) => toggle.checked).map((toggle) => toggle.value));
  document.querySelectorAll("[data-comparison-environment]").forEach((element) => {
    element.hidden = !selected.has(element.dataset.comparisonEnvironment);
  });
  document.querySelectorAll("[data-comparison-environment-card]").forEach((element) => {
    element.hidden = !selected.has(element.dataset.comparisonEnvironmentCard);
  });
  if (allToggle) {
    allToggle.checked = selected.size === toggles.length;
    allToggle.indeterminate = selected.size > 0 && selected.size < toggles.length;
  }
  const count = root.querySelector("[data-environment-count]");
  if (count) count.textContent = `${selected.size} of ${toggles.length} selected`;
}

function initializeEnvironmentSelector() {
  updateEnvironmentSelection();
}

function updateComparison() {
  const body = document.querySelector("[data-comparison-rows]");
  if (!body) return;
  const rows = Array.from(body.querySelectorAll("[data-comparison-row]"));
  const query = document.querySelector("[data-comparison-search]")?.value.trim().toLowerCase() || "";
  const filter = document.querySelector("[data-comparison-filter]")?.value || "all";
  const sort = document.querySelector("[data-comparison-sort]")?.value || "key-asc";
  const matchesFilter = (row) => filter === "all" || row.dataset[filter] === "true";
  const attentionScore = (row) => Number(row.dataset.pending === "true") * 2 + Number(row.dataset.missing === "true");
  rows.sort((left, right) => {
    if (sort === "key-desc") return right.dataset.key.localeCompare(left.dataset.key);
    if (sort === "attention") {
      const difference = attentionScore(right) - attentionScore(left);
      if (difference !== 0) return difference;
    }
    return left.dataset.key.localeCompare(right.dataset.key);
  });
  let visible = 0;
  rows.forEach((row) => {
    const detail = document.getElementById(row.querySelector("[data-comparison-toggle]")?.dataset.comparisonToggle || "");
    body.append(row);
    if (detail) body.append(detail);
    const matches = (!query || row.dataset.key.toLowerCase().includes(query)) && matchesFilter(row);
    row.hidden = !matches;
    if (detail && !matches) {
      detail.hidden = true;
      row.classList.remove("is-expanded");
      row.querySelector("[data-comparison-toggle]")?.setAttribute("aria-expanded", "false");
    }
    if (matches) {
      visible += 1;
      const index = row.querySelector("[data-comparison-index]");
      if (index) index.textContent = String(visible);
    }
  });
  const count = document.querySelector("[data-comparison-count]");
  if (count) count.textContent = `${visible} of ${rows.length} keys`;
  const empty = document.querySelector("[data-comparison-empty]");
  if (empty) empty.hidden = visible !== 0;
}

function initializeGlobalSearch() {
  const root = document.querySelector("[data-global-search]");
  const input = root?.querySelector("[data-global-search-input]");
  const panel = root?.querySelector("[data-global-search-results]");
  if (!root || !input || !panel) return;
  let timer;
  let controller;
  let activeIndex = -1;
  const links = () => Array.from(panel.querySelectorAll("[data-global-search-result]"));
  const setOpen = (open) => {
    panel.hidden = !open;
    input.setAttribute("aria-expanded", String(open));
  };
  const setActive = (index) => {
    const results = links();
    activeIndex = results.length === 0 ? -1 : Math.max(0, Math.min(index, results.length - 1));
    results.forEach((link, resultIndex) => link.classList.toggle("is-active", resultIndex === activeIndex));
    results[activeIndex]?.scrollIntoView({ block: "nearest" });
  };
  const message = (text) => {
    const paragraph = document.createElement("p");
    paragraph.textContent = text;
    panel.replaceChildren(paragraph);
    activeIndex = -1;
    setOpen(true);
  };
  const render = (results) => {
    panel.replaceChildren();
    activeIndex = -1;
    if (results.length === 0) {
      message("No authorized configuration keys match this search.");
      return;
    }
    results.forEach((result) => {
      const link = document.createElement("a");
      link.className = "global-search-result";
      link.dataset.globalSearchResult = "";
      link.setAttribute("role", "option");
      link.href = `/environments/${encodeURIComponent(result.environment_id)}/variables?q=${encodeURIComponent(result.key)}`;
      const key = document.createElement("strong");
      key.textContent = result.key;
      const location = document.createElement("small");
      location.textContent = `${result.app_name} / ${result.environment_name}`;
      const metadata = document.createElement("em");
      metadata.textContent = `${result.visibility} · ${result.value_type}`;
      link.append(key, location, metadata);
      panel.append(link);
    });
    setOpen(true);
  };
  const search = () => {
    const query = input.value.trim();
    if (query.length < 2) {
      controller?.abort();
      message("Type at least two characters.");
      return;
    }
    controller?.abort();
    controller = new AbortController();
    fetch(`/api/search/keys?q=${encodeURIComponent(query)}`, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      signal: controller.signal
    })
      .then((response) => {
        if (!response.ok) throw new Error("key search failed");
        return response.json();
      })
      .then(render)
      .catch((error) => {
        if (error.name !== "AbortError") message("Search is temporarily unavailable.");
      });
  };
  input.addEventListener("input", () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(search, 180);
  });
  input.addEventListener("focus", () => {
    if (panel.childElementCount > 0) setOpen(true);
  });
  input.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      setOpen(false);
      input.blur();
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive(activeIndex + 1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive(activeIndex <= 0 ? links().length - 1 : activeIndex - 1);
    } else if (event.key === "Enter" && activeIndex >= 0) {
      event.preventDefault();
      links()[activeIndex]?.click();
    }
  });
  root.addEventListener("focusout", () => {
    window.setTimeout(() => {
      if (!root.contains(document.activeElement)) setOpen(false);
    }, 0);
  });
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      input.focus();
      input.select();
      setOpen(true);
    }
  });
}

document.addEventListener("click", (event) => {
  if (openSelectMenu
      && !openSelectMenu.trigger.contains(event.target)
      && !openSelectMenu.menu.contains(event.target)) {
    closeCustomSelect();
  }
  const themeButton = event.target.closest("[data-theme-toggle]");
  if (themeButton) {
    setTheme(currentTheme() === "dark" ? "light" : "dark");
    return;
  }
  const sidebarButton = event.target.closest("[data-sidebar-toggle]");
  if (sidebarButton) {
    setSidebarCollapsed(document.documentElement.dataset.sidebar !== "collapsed", true);
    return;
  }
  const viewButton = event.target.closest("[data-service-view]");
  if (viewButton) {
    setServiceView(viewButton.dataset.serviceView, true);
    return;
  }
  const comparisonToggle = event.target.closest("[data-comparison-toggle]");
  if (comparisonToggle) {
    const row = comparisonToggle.closest("[data-comparison-row]");
    if (row) setComparisonExpanded(row, comparisonToggle.getAttribute("aria-expanded") !== "true");
    return;
  }
  const comparisonAction = event.target.closest("[data-comparison-action]");
  if (comparisonAction) {
    const row = comparisonAction.closest("[data-comparison-row]");
    if (!row) return;
    setComparisonExpanded(row, true);
    const detailId = row.querySelector("[data-comparison-toggle]")?.dataset.comparisonToggle;
    const detail = detailId ? document.getElementById(detailId) : null;
    const selector = comparisonAction.dataset.comparisonAction === "delete"
      ? "[data-comparison-delete]"
      : "[data-comparison-edit]";
    const action = detail?.querySelector(selector);
    if (action) {
      action.open = true;
      action.querySelector("summary")?.focus();
    }
    return;
  }
  const expandAll = event.target.closest("[data-comparison-expand]");
  if (expandAll) {
    document.querySelectorAll("[data-comparison-row]:not([hidden])").forEach((row) => setComparisonExpanded(row, true));
    return;
  }
  const collapseAll = event.target.closest("[data-comparison-collapse]");
  if (collapseAll) {
    document.querySelectorAll("[data-comparison-row]").forEach((row) => setComparisonExpanded(row, false));
    return;
  }
  const editButton = event.target.closest("[data-inline-edit]");
  if (editButton) {
    const editor = document.getElementById(editButton.dataset.inlineEdit);
    if (!editor) return;
    const willOpen = editor.hidden;
    document.querySelectorAll(".inline-editor-row:not([hidden])").forEach((row) => {
      row.hidden = true;
      const trigger = document.querySelector(`[data-inline-edit="${row.id}"]`);
      if (trigger) trigger.setAttribute("aria-expanded", "false");
    });
    editor.hidden = !willOpen;
    editButton.setAttribute("aria-expanded", String(willOpen));
    if (willOpen) editor.querySelector("[name='value_0']")?.focus();
    return;
  }
  const closeButton = event.target.closest("[data-inline-close]");
  if (closeButton) {
    const editor = document.getElementById(closeButton.dataset.inlineClose);
    if (!editor) return;
    editor.hidden = true;
    const trigger = document.querySelector(`[data-inline-edit="${editor.id}"]`);
    if (trigger) trigger.setAttribute("aria-expanded", "false");
    trigger?.focus();
    return;
  }
  const applyVisible = event.target.closest("[data-import-apply-visible]");
  if (applyVisible) {
    const visibility = document.querySelector("[data-import-bulk-visibility]")?.value;
    const visibleRows = Array.from(document.querySelectorAll("[data-import-row]:not([hidden])"));
    visibleRows.forEach((row) => {
      const select = row.querySelector("[data-import-visibility]");
      if (select) select.value = visibility;
    });
    const status = document.querySelector("[data-import-status]");
    if (status) status.textContent = `${visibleRows.length} visible row(s) set to ${visibility}.`;
    return;
  }
  const button = event.target.closest("[data-copy-all], [data-copy-selected]");
  if (!button) return;
  const selector = button.dataset.copyAll || button.dataset.copySelected;
  const source = document.querySelector(selector);
  const status = document.querySelector(".copy-status");
  if (!source || !status) return;
  let text = source.value;
  if (button.dataset.copySelected) {
    const selected = new Set(
      Array.from(document.querySelectorAll('input[name="export_line"]:checked'))
        .map((input) => Number(input.value))
    );
    text = text.split("\n").filter((_line, index) => selected.has(index)).join("\n");
    if (text) text += "\n";
  }
  void writeClipboard(text, status);
});

document.addEventListener("submit", (event) => {
  const form = event.target.closest("form[data-copy-form]");
  if (!form) return;
  event.preventDefault();
  const status = form.querySelector(".copy-status");
  fetch(form.action, { method: "POST", body: new FormData(form), credentials: "same-origin" })
    .then((response) => {
      if (!response.ok) throw new Error("copy request failed");
      return response.text();
    })
    .then((text) => writeClipboard(text, status))
    .catch(() => { status.textContent = "Copy failed. Refresh privileged authentication when required."; });
});

document.addEventListener("change", (event) => {
  const environmentAll = event.target.closest("[data-environment-toggle-all]");
  if (environmentAll) {
    const toggles = Array.from(document.querySelectorAll("[data-environment-toggle]"));
    toggles.forEach((toggle, index) => { toggle.checked = environmentAll.checked || index === 0; });
    updateEnvironmentSelection(toggles[0]);
    return;
  }
  const environmentToggle = event.target.closest("[data-environment-toggle]");
  if (environmentToggle) {
    updateEnvironmentSelection(environmentToggle);
    return;
  }
  const serviceSort = event.target.closest("[data-service-sort], [data-service-status]");
  if (serviceSort) {
    updateServiceCatalog();
    return;
  }
  const comparisonControl = event.target.closest("[data-comparison-filter], [data-comparison-sort]");
  if (comparisonControl) {
    updateComparison();
    return;
  }
  const valueSource = event.target.closest("[data-value-source]");
  if (valueSource) {
    updateValueSource(valueSource);
    return;
  }
  const logoInput = event.target.closest("[data-logo-input]");
  if (logoInput) {
    const preview = document.querySelector("[data-logo-preview]");
    const wrapper = document.querySelector("[data-logo-preview-wrap]");
    const file = logoInput.files?.[0];
    if (!preview || !wrapper) return;
    if (preview.dataset.objectUrl) URL.revokeObjectURL(preview.dataset.objectUrl);
    if (!file) {
      preview.removeAttribute("src");
      delete preview.dataset.objectUrl;
      wrapper.hidden = true;
      return;
    }
    const objectUrl = URL.createObjectURL(file);
    preview.src = objectUrl;
    preview.dataset.objectUrl = objectUrl;
    wrapper.hidden = false;
    return;
  }
  const typeSelect = event.target.closest('select[name="value_type_0"], [data-value-type]');
  if (!typeSelect) return;
  const form = typeSelect.closest("form");
  const current = typeSelect.dataset.valueType !== undefined
    ? form?.querySelector("[data-value-input]")
    : form?.querySelector('[name="value_0"]');
  if (!current) return;
  const replacement = valueControl(typeSelect.value, current.value, current.name);
  const customSelect = customSelectInstances.get(current);
  if (customSelect) {
    if (openSelectMenu?.trigger === customSelect.trigger) closeCustomSelect();
    customSelect.trigger.remove();
    customSelect.menu.remove();
  }
  current.replaceWith(replacement);
  initializeCustomSelects(form);
  (customSelectInstances.get(replacement)?.trigger || replacement).focus();
});

document.addEventListener("input", (event) => {
  const serviceSearch = event.target.closest("[data-service-search]");
  if (serviceSearch) {
    updateServiceCatalog();
    return;
  }
  const comparisonSearch = event.target.closest("[data-comparison-search]");
  if (comparisonSearch) {
    updateComparison();
    return;
  }
  const search = event.target.closest("[data-import-search]");
  if (!search) return;
  const query = search.value.trim().toLowerCase();
  const rows = Array.from(document.querySelectorAll("[data-import-row]"));
  let visible = 0;
  rows.forEach((row) => {
    const matches = !query || row.dataset.importKey.toLowerCase().includes(query);
    row.hidden = !matches;
    if (matches) visible += 1;
  });
  const status = document.querySelector("[data-import-status]");
  if (status) status.textContent = `Showing ${visible} of ${rows.length}`;
});

document.addEventListener("DOMContentLoaded", () => {
  updateThemeControls();
  initializeApplicationShell();
  initializeGlobalSearch();
  initializeServiceCatalog();
  initializeEnvironmentSelector();
  initializeValueSources();
  initializeCustomSelects();
  updateComparison();
});

window.addEventListener("resize", closeCustomSelect);
window.addEventListener("scroll", closeCustomSelect, true);
}());
