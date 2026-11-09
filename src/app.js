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

function run() {
  const text = input.value;
  if (!text.trim()) {
    showEmpty();
    return;
  }
  let result;
  try {
    result = processConfig(text, platform.value);
  } catch {
    output.value = "";
    setActions();
    setStatus("Could not obfuscate this config. Nothing was uploaded.", "error");
    renderEmptySummary();
    return;
  }
  output.value = result.output;
  setActions();
  setStatus(statusMessage(result), result.uncertain ? "warn" : "ok");
  renderSummary(result);
}

function readFile(file) {
  if (file.size > MAX_BYTES) {
    setStatus("That file is larger than 2 MB. Choose a smaller text config.", "error");
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    input.value = typeof reader.result === "string" ? reader.result : "";
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
  if (total === 0) {
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent = "No secret fields matched. A password hidden in a description, banner, or unusual command may still be present.";
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
  setStatus("Paste a configuration or choose a file.", "warn");
  renderEmptySummary();
}

function clearAll() {
  input.value = "";
  output.value = "";
  fileInput.value = "";
  platform.value = "auto";
  setActions();
  setStatus("Cleared. The config is not stored in this browser.", "ok");
  renderEmptySummary();
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
