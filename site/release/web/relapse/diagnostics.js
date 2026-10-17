"use strict";

(() => {
  const scriptUrl = document.currentScript && document.currentScript.src
    ? document.currentScript.src
    : window.location.href;
  const endpoint = new URL("../api/relapse/diagnostics", scriptUrl).toString();
  const sessionId = makeSessionId();
  const pending = [];
  const maxLines = 500;
  let sequence = 0;
  let sending = false;
  let timer = null;
  let retryTimer = null;
  let lastFailure = false;

  function makeSessionId() {
    const bytes = new Uint8Array(16);
    if (window.crypto && typeof window.crypto.getRandomValues === "function") {
      window.crypto.getRandomValues(bytes);
    } else {
      for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  function clean(value) {
    return String(value)
      .replace(/\b0x[0-9a-f]{6,16}\b/gi, "0x[redacted]")
      .replace(/[\r\n\t]+/g, " ")
      .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "")
      .slice(0, 800);
  }

  function setStatus(message, failed = false) {
    const node = document.getElementById("diagnostics-status");
    if (!node) return;
    node.textContent = message;
    node.classList.toggle("error", failed);
  }

  function schedule(delay = lastFailure ? 5000 : 250) {
    if (timer !== null || retryTimer !== null || pending.length === 0) return;
    timer = window.setTimeout(() => {
      timer = null;
      void flush();
    }, delay);
  }

  async function flush() {
    if (sending || pending.length === 0) return;
    sending = true;
    const batch = pending.splice(0, 20);
    const body = JSON.stringify({
      session_id: sessionId,
      firmware: window.fw_str || ((navigator.userAgent.match(/PlayStation 5\/(\d+\.\d+)/) || [])[1]) || "unknown",
      lines: batch,
    });

    try {
      const response = await fetch(endpoint, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body,
        keepalive: true,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      lastFailure = false;
      setStatus("Diagnostics are reaching this site’s server. Memory addresses are removed.");
    } catch (error) {
      pending.unshift(...batch);
      lastFailure = true;
      setStatus("Diagnostics could not reach the server yet; the page will retry.", true);
      if (retryTimer === null) {
        retryTimer = window.setTimeout(() => {
          retryTimer = null;
          void flush();
        }, 5000);
      }
    } finally {
      sending = false;
      if (pending.length > 0 && !lastFailure) schedule(100);
    }
  }

  function log(message, level = "log") {
    if (sequence >= maxLines) return;
    sequence += 1;
    pending.push({
      seq: sequence,
      level: ["info", "success", "error", "log"].includes(level) ? level : "log",
      message: clean(message),
      client_time: new Date().toISOString(),
    });
    if (level === "error" || pending.length >= 5) {
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
      void flush();
    } else {
      schedule();
    }
  }

  window.__relapseDiagnostics = { log, flush };
  window.addEventListener("error", (event) => {
    if (event.target && event.target !== window) {
      const resource = event.target.src || event.target.href || "resource";
      log(`Resource load error: ${String(resource).split("/").slice(-2).join("/")}`, "error");
      return;
    }
    const location = event.filename ? ` (${event.filename.split("/").slice(-2).join("/")}:${event.lineno || 0})` : "";
    log(`JavaScript error: ${event.message || "unknown"}${location}`, "error");
  });
  window.addEventListener("unhandledrejection", (event) => {
    const reason = event.reason && event.reason.message ? event.reason.message : event.reason;
    log(`Unhandled promise rejection: ${reason || "unknown"}`, "error");
  });
  window.addEventListener("pagehide", () => { void flush(); });
  window.addEventListener("DOMContentLoaded", () => {
    setStatus("Run messages and JavaScript errors are automatically sent to this site’s server for troubleshooting. Memory addresses are removed.");
  });
  log("PS5 page diagnostics initialized", "info");
})();
