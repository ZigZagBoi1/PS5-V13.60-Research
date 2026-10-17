"use strict";

const statusNode = document.getElementById("status");
const loaderReady = document.getElementById("loader-ready");
const sendButton = document.getElementById("send-payload");
const resultNode = document.getElementById("send-result");
const hvConfirmed = document.getElementById("hv-confirmed");

function diagnostic(message, level = "info") {
  if (window.__relapseDiagnostics && typeof window.__relapseDiagnostics.log === "function") {
    window.__relapseDiagnostics.log(message, level);
  }
}

function show(node, message, kind) {
  node.textContent = message;
  node.className = kind || "";
}

function onTargetConsole() {
  return /^Mozilla\/5\.0 \(PlayStation; PlayStation 5\/13\.60\)/.test(navigator.userAgent);
}

async function loadStatus() {
  diagnostic("HV stage page opened");
  if (!onTargetConsole()) {
    show(statusNode, "Open this page on the PS5 running firmware 13.60. The HV sender does not accept requests from desktop browsers.", "error");
    return;
  }
  try {
    const response = await fetch("api/hv/status", { cache: "no-store", credentials: "same-origin" });
    const result = await response.json();
    if (!response.ok || !result.eligible) throw new Error(result.error || "The server could not verify this PS5 session.");
    show(statusNode, `PS5 ${result.firmware} · ${result.payload_bytes.toLocaleString()} byte payload ready · delivery target ${result.target}:9021. Complete Relapse before sending.`, "good");
    diagnostic(`HV server ready: ${result.firmware}, ${result.payload_bytes} byte payload, ELF loader port ${result.loader_port}; HV not yet confirmed.`, "success");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    show(statusNode, message, "error");
    diagnostic(`HV status check failed: ${message}`, "error");
  }
}

loaderReady.addEventListener("change", () => {
  sendButton.disabled = !loaderReady.checked;
  if (loaderReady.checked) diagnostic("User confirmed the Relapse ELF loader is listening on port 9021.");
});

hvConfirmed.addEventListener("change", () => {
  if (hvConfirmed.checked) {
    diagnostic("User reports seeing the post-resume hypervisor success notification.", "success");
  }
});

sendButton.addEventListener("click", async () => {
  if (!loaderReady.checked || sendButton.disabled) return;
  sendButton.disabled = true;
  loaderReady.disabled = true;
  show(resultNode, "Sending once to the ELF loader on this PS5…", "");
  diagnostic("Byepervisor payload send requested.");
  try {
    const response = await fetch("api/hv/send", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ firmware: "13.60", elfldr_ready: true }),
      cache: "no-store",
    });
    const result = await response.json();
    if (!response.ok || !result.sent) throw new Error(result.error || "Payload transfer failed.");
    show(resultNode, `${result.message} (${result.bytes_sent.toLocaleString()} bytes.)`, "good");
    diagnostic(`Byepervisor payload transfer reported complete: ${result.bytes_sent} bytes to port ${result.port}; this does not confirm HV success.`, "success");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    show(resultNode, `${message} Check the PS5 screen before trying again; the page will not retry automatically.`, "error");
    diagnostic(`Byepervisor payload transfer failed: ${message}`, "error");
    sendButton.disabled = false;
    loaderReady.disabled = false;
  }
});

loadStatus();
