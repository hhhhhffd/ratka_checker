const API_BASE = "/api";
const POLL_INTERVAL_MS = 1500;

const form = document.querySelector("#scanForm");
const fileInput = document.querySelector("#fileInput");
const dropzone = document.querySelector("#dropzone");
const fileTitle = document.querySelector("#fileTitle");
const fileMeta = document.querySelector("#fileMeta");
const submitButton = document.querySelector("#submitButton");
const clearButton = document.querySelector("#clearButton");
const resultPanel = document.querySelector("#resultPanel");
const resultTitle = document.querySelector("#resultTitle");
const riskScore = document.querySelector("#riskScore");
const scanStatus = document.querySelector("#scanStatus");
const scanHash = document.querySelector("#scanHash");
const summaryText = document.querySelector("#summaryText");
const findings = document.querySelector("#findings");
const rawPanel = document.querySelector("#rawPanel");
const rawJson = document.querySelector("#rawJson");
const copyJsonButton = document.querySelector("#copyJsonButton");
const healthStatus = document.querySelector("#healthStatus");

let activePollController = null;

checkHealth();

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  await uploadScan();
});

fileInput.addEventListener("change", updateSelectedFile);
clearButton.addEventListener("click", clearState);
copyJsonButton.addEventListener("click", copyJson);

for (const eventName of ["dragenter", "dragover"]) {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.add("dragging");
  });
}

for (const eventName of ["dragleave", "drop"]) {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.remove("dragging");
  });
}

dropzone.addEventListener("drop", (event) => {
  const [file] = event.dataTransfer.files;
  if (!file) {
    return;
  }
  fileInput.files = event.dataTransfer.files;
  updateSelectedFile();
});

async function checkHealth() {
  try {
    const response = await fetch("/health", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    healthStatus.textContent = "API online";
    healthStatus.className = "health ok";
  } catch (error) {
    healthStatus.textContent = "API offline";
    healthStatus.className = "health bad";
  }
}

function updateSelectedFile() {
  const file = fileInput.files[0];
  if (!file) {
    fileTitle.textContent = "Choose .jar file";
    fileMeta.textContent = "Maximum upload is controlled by the backend.";
    return;
  }
  fileTitle.textContent = file.name;
  fileMeta.textContent = `${formatBytes(file.size)} selected`;
}

async function uploadScan() {
  const file = fileInput.files[0];

  if (!file) {
    renderError(".jar file is required.");
    return;
  }
  if (!file.name.toLowerCase().endsWith(".jar")) {
    renderError("Only .jar files are accepted.");
    return;
  }

  stopPolling();
  submitButton.disabled = true;
  submitButton.textContent = "Uploading";

  const body = new FormData();
  body.append("file", file);

  try {
    const scan = await requestJson(`${API_BASE}/scans`, {
      method: "POST",
      body,
    });
    renderScan(scan);
    if (scan.status === "pending") {
      pollScan(scan.scan_id);
    }
  } catch (error) {
    renderError(error.message);
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = "Scan file";
  }
}

async function pollScan(scanId) {
  activePollController = new AbortController();
  while (!activePollController.signal.aborted) {
    await delay(POLL_INTERVAL_MS);
    if (activePollController.signal.aborted) {
      return;
    }

    try {
      const scan = await requestJson(`${API_BASE}/scans/${scanId}`, {
        signal: activePollController.signal,
      });
      renderScan(scan);
      if (scan.status !== "pending") {
        stopPolling();
        return;
      }
    } catch (error) {
      if (error.name !== "AbortError") {
        renderError(error.message);
      }
      stopPolling();
      return;
    }
  }
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch (error) {
      throw new Error(`Invalid JSON from server: ${error.message}`);
    }
  }

  if (!response.ok) {
    const message = data?.message || data?.error || `HTTP ${response.status}`;
    throw new Error(message);
  }
  return data;
}

function renderScan(scan) {
  resultPanel.hidden = false;
  rawPanel.hidden = false;

  const verdict = scan.verdict || "pending";
  const score = Number(scan.risk_score || 0);

  resultTitle.textContent = verdict;
  resultTitle.className = "";
  riskScore.textContent = score;
  riskScore.className = `score ${verdict}`;
  scanStatus.textContent = scan.status;
  scanHash.textContent = scan.sha256 || "-";
  summaryText.textContent = scan.summary || "Scan is still running.";
  rawJson.textContent = JSON.stringify(scan, null, 2);

  findings.replaceChildren();
  if (!scan.findings || scan.findings.length === 0) {
    findings.append(emptyFinding());
    return;
  }

  for (const finding of scan.findings) {
    findings.append(renderFinding(finding));
  }
}

function renderFinding(finding) {
  const item = document.createElement("article");
  item.className = "finding";

  const head = document.createElement("div");
  head.className = "finding-head";

  const rule = document.createElement("div");
  rule.className = "rule-id";
  rule.textContent = finding.rule_id;

  const severity = document.createElement("div");
  severity.className = `severity ${finding.severity}`;
  severity.textContent = finding.severity;

  const message = document.createElement("p");
  message.textContent = finding.message;

  head.append(rule, severity);
  item.append(head, message);
  return item;
}

function emptyFinding() {
  const item = document.createElement("article");
  item.className = "finding";
  const message = document.createElement("p");
  message.textContent = "No findings returned.";
  item.append(message);
  return item;
}

function renderError(message) {
  resultPanel.hidden = false;
  rawPanel.hidden = true;
  resultTitle.textContent = "Error";
  riskScore.textContent = "!";
  riskScore.className = "score malicious";
  scanStatus.textContent = "failed";
  scanHash.textContent = "-";
  summaryText.textContent = message;
  findings.replaceChildren();
}

function clearState() {
  stopPolling();
  form.reset();
  updateSelectedFile();
  resultPanel.hidden = true;
  rawPanel.hidden = true;
}

async function copyJson() {
  if (!rawJson.textContent) {
    return;
  }
  await navigator.clipboard.writeText(rawJson.textContent);
  copyJsonButton.textContent = "Copied";
  setTimeout(() => {
    copyJsonButton.textContent = "Copy";
  }, 1200);
}

function stopPolling() {
  if (activePollController) {
    activePollController.abort();
    activePollController = null;
  }
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function formatBytes(bytes) {
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(value >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}
