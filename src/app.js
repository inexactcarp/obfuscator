import { scanPrefixes } from "./prefixes.js";
import { CATEGORIES, PLATFORM_LABELS, processConfig } from "./process.js";

const form = document.querySelector("#controls");
const input = document.querySelector("#input");
const output = document.querySelector("#output");
const platform = document.querySelector("#platform");
const fileInput = document.querySelector("#file");
const status = document.querySelector("#status");
const summary = document.querySelector("#summary");
const copyButton = document.querySelector("#copy");
const downloadButton = document.querySelector("#download");
const clearButton = document.querySelector("#clear");
const prefixList = document.querySelector("#prefix-list");
const prefixAll = document.querySelector("#prefix-all");
const setAllPrefixes = document.querySelector("#set-all-prefixes");
const placeholderStyle = document.querySelector("#placeholder-style");
const placeholderCustomWrap = document.querySelector("#placeholder-custom-wrap");
const placeholderCustom = document.querySelector("#placeholder-custom");

let prefixSignature = null;

const MAX_BYTES = 2 * 1024 * 1024;

form.addEventListener("submit", (event) => {
  event.preventDefault();
  run();
});

platform.addEventListener("change", () => {
  if (input.value.trim()) run();
});

fileInput.addEventListener("change", () => {
  const file = fileInput.files && fileInput.files[0];
  fileInput.value = "";
  if (file) readFile(file);
});

clearButton.addEventListener("click", clearAll);
copyButton.addEventListener("click", copyOutput);
downloadButton.addEventListener("click", downloadOutput);

document.addEventListener("dragover", (event) => {
  event.preventDefault();
});

document.addEventListener("drop", (event) => {
  event.preventDefault();
  const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
  if (file) readFile(file);
});

input.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
    event.preventDefault();
    run();
  }
});

input.addEventListener("input", () => {
  refreshPrefixes();
});

prefixList.addEventListener("input", () => {
  if (output.value) run();
});

setAllPrefixes.addEventListener("click", applyAllPrefixes);
placeholderStyle.addEventListener("change", () => {
  placeholderCustomWrap.hidden = placeholderStyle.value !== "custom";
  if (output.value) run();
});
placeholderCustom.addEventListener("input", () => {
  if (placeholderStyle.value === "custom" && output.value) run();
});

function run() {
  const text = input.value;
  if (!text.trim()) {
    showEmpty();
    return;
  }
  refreshPrefixes();
  const edits = readPrefixEdits();
  let result;
  try {
    result = processConfig(text, platform.value, edits.values, { placeholder: currentPlaceholder() });
  } catch {
    output.value = "";
    setActions();
    setStatus("Could not obfuscate this config. Nothing was uploaded.", "error");
    renderEmptySummary();
    return;
  }
  output.value = result.output;
  setActions();
  const kind = edits.invalid ? "warn" : (result.uncertain ? "warn" : "ok");
  const dotted = edits.invalid ? " A prefix without a dot was left unchanged. Use a value like x.x." : "";
  setStatus(statusMessage(result) + dotted, kind);
  renderSummary(result);
}

function readFile(file) {
  if (file.size > MAX_BYTES) {
    setStatus("That file is larger than 2 MB. Choose a smaller text file.", "error");
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    const text = String(reader.result ?? "").replace(/^\uFEFF/, "").replace(/\u0000/g, "");
    if (!text.trim()) {
      setStatus("That file did not contain readable text.", "error");
      return;
    }
    input.value = text;
    run();
  };
  reader.onerror = () => {
    setStatus("Could not read that file.", "error");
  };
  reader.readAsText(file);
}

function statusMessage(result) {
  if (result.uncertain) {
    return "Detection was uncertain, so the platform is unknown. Secret patterns were still applied. Set the platform if you know it.";
  }
  const label = PLATFORM_LABELS[result.platform] || "Unknown";
  if (platform.value === "auto") return `Detected ${label}.`;
  return `Using ${label}.`;
}

function renderSummary(result) {
  summary.replaceChildren();
  const total = Object.values(result.counts).reduce((sum, count) => sum + count, 0);
  const heading = document.createElement("p");
  heading.textContent = total === 1
    ? "1 secret field replaced."
    : `${total} secret fields replaced.`;
  summary.appendChild(heading);
  if (result.addressesRewritten) {
    const rewritten = document.createElement("p");
    rewritten.textContent = result.addressesRewritten === 1
      ? "1 IPv4 address had its first two octets rewritten."
      : `${result.addressesRewritten} IPv4 addresses had their first two octets rewritten.`;
    summary.appendChild(rewritten);
  }
  if (total === 0) {
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent = "No secret fields matched. A password hidden in a description, remark, or MOTD banner may still be present.";
    summary.appendChild(note);
    return;
  }
  const list = document.createElement("ul");
  for (const category of CATEGORIES) {
    const count = result.counts[category.id] || 0;
    if (!count) continue;
    const item = document.createElement("li");
    item.textContent = `${category.label}: ${count}`;
    list.appendChild(item);
  }
  summary.appendChild(list);
}

function renderEmptySummary() {
  summary.replaceChildren();
  const note = document.createElement("p");
  note.className = "muted";
  note.textContent = "No results yet. Counts show how many fields were replaced. Values are not listed.";
  summary.appendChild(note);
}

function showEmpty() {
  output.value = "";
  setActions();
  refreshPrefixes();
  setStatus("Paste a configuration or choose a file.", "warn");
  renderEmptySummary();
}

function clearAll() {
  input.value = "";
  output.value = "";
  fileInput.value = "";
  platform.value = "auto";
  setActions();
  refreshPrefixes();
  setStatus("Cleared. The config is not stored in this browser.", "ok");
  renderEmptySummary();
}

function refreshPrefixes() {
  const found = scanPrefixes(input.value);
  const signature = found.join("\n");
  if (signature === prefixSignature) return;
  const previous = readPrefixEdits();
  prefixSignature = signature;
  prefixList.replaceChildren();
  if (found.length === 0) {
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent = "No IPv4 addresses in the config yet.";
    prefixList.appendChild(note);
    return;
  }
  for (const prefix of found) {
    const row = document.createElement("label");
    row.className = "prefix-row";
    const name = document.createElement("span");
    name.className = "prefix-found";
    name.textContent = prefix;
    const arrow = document.createElement("span");
    arrow.className = "prefix-arrow";
    arrow.textContent = "→";
    arrow.setAttribute("aria-hidden", "true");
    const field = document.createElement("input");
    field.type = "text";
    field.spellcheck = false;
    field.autocomplete = "off";
    field.dataset.prefix = prefix;
    field.value = Object.prototype.hasOwnProperty.call(previous, prefix) ? previous[prefix] : prefix;
    field.setAttribute("aria-label", `Replacement for ${prefix}`);
    row.append(name, arrow, field);
    prefixList.appendChild(row);
  }
}

function applyAllPrefixes() {
  const value = prefixAll.value.trim();
  if (!value.includes(".")) {
    setStatus("A prefix needs a dot, for example x.x.", "warn");
    prefixAll.focus();
    return;
  }
  const fields = prefixList.querySelectorAll("input[data-prefix]");
  if (fields.length === 0) {
    setStatus("No IPv4 prefixes to change yet.", "warn");
    return;
  }
  for (const field of fields) field.value = value;
  if (input.value.trim()) run();
}

function currentPlaceholder() {
  if (placeholderStyle.value === "custom") return placeholderCustom.value;
  return placeholderStyle.value;
}

function readPrefixEdits() {
  const values = {};
  let invalid = false;
  for (const field of prefixList.querySelectorAll("input[data-prefix]")) {
    const value = field.value.trim();
    const unchanged = !value || value === field.dataset.prefix;
    if (!unchanged && !value.includes(".")) {
      invalid = true;
      field.classList.add("invalid");
    } else {
      field.classList.remove("invalid");
    }
    values[field.dataset.prefix] = field.value;
  }
  return { values, invalid };
}

async function copyOutput() {
  if (!output.value) return;
  try {
    await navigator.clipboard.writeText(output.value);
    setStatus("Copied the obfuscated config.", "ok");
  } catch {
    output.focus();
    output.select();
    setStatus("Clipboard access was blocked. The obfuscated output is selected so you can copy it.", "warn");
  }
}

function downloadOutput() {
  if (!output.value) return;
  const blob = new Blob([output.value], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "obfuscated.cfg";
  link.click();
  URL.revokeObjectURL(url);
  setStatus("Download started. The file is the obfuscated config.", "ok");
}

function setActions() {
  const ready = output.value.length > 0;
  copyButton.disabled = !ready;
  downloadButton.disabled = !ready;
}

function setStatus(message, kind) {
  status.textContent = message;
  status.className = kind ? `status ${kind}` : "status";
}

refreshPrefixes();
