"use strict";

const statusNode = document.getElementById("status");
const loaderReady = document.getElementById("loader-ready");
const sendButton = document.getElementById("send-payload");
const resultNode = document.getElementById("send-result");
const hvConfirmed = document.getElementById("hv-confirmed");
let readySessionId = null;
let attempted = false;
const handoffSessionId = new URLSearchParams(window.location.search).get("relapse_session_id");

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
    if (!result.relapse_ready || !result.relapse_session_id || result.relapse_session_id !== handoffSessionId) {
      const message = result.transfer_state
        ? "An HV delivery was already attempted for this console. Check the console before another attempt."
        : "This HV page is separate, but the current sender still requires a Relapse-recorded session. An independent HV launcher is not implemented here.";
      show(statusNode, message, "error");
      return;
    }
    readySessionId = result.relapse_session_id;
    loaderReady.disabled = false;
    show(statusNode, `PS5 ${result.firmware} · verified ${result.payload_bytes.toLocaleString()} byte payload · this sender is tied to a Relapse session.`, "good");
    diagnostic(`HV server ready: ${result.firmware}, ${result.payload_bytes} byte payload, ELF loader port ${result.loader_port}; HV not yet confirmed.`, "success");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    show(statusNode, message, "error");
    diagnostic(`HV status check failed: ${message}`, "error");
  }
}

loaderReady.addEventListener("change", () => {
  sendButton.disabled = attempted || !readySessionId || !loaderReady.checked;
  if (loaderReady.checked) diagnostic("User confirmed the Relapse ELF loader is listening on port 9021.");
});

hvConfirmed.addEventListener("change", () => {
  if (hvConfirmed.checked) {
    diagnostic("User reports seeing the post-resume hypervisor success notification.", "success");
  }
});

sendButton.addEventListener("click", async () => {
  if (attempted || !readySessionId || !loaderReady.checked || sendButton.disabled) return;
  attempted = true;
  sendButton.disabled = true;
  loaderReady.disabled = true;
  show(resultNode, "Sending once to the ELF loader on this PS5…", "");
  diagnostic("Byepervisor payload send requested.");
  try {
    const response = await fetch("api/hv/send", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ firmware: "13.60", elfldr_ready: true, relapse_session_id: readySessionId }),
      cache: "no-store",
    });
    const result = await response.json();
    if (!response.ok || !result.sent) throw new Error(result.error || "Payload transfer failed.");
    show(resultNode, `${result.message} (${result.bytes_sent.toLocaleString()} bytes.)`, "good");
    diagnostic(`Byepervisor payload transfer reported complete: ${result.bytes_sent} bytes to port ${result.port}; this does not confirm HV success.`, "success");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    show(resultNode, `${message} Delivery may already have occurred. This session stays locked; check the PS5 screen and restart the console before running a new chain.`, "error");
    diagnostic(`Byepervisor payload transfer failed: ${message}`, "error");
  }
});

loadStatus();
