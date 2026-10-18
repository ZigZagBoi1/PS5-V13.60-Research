"use strict";

const startButton = document.getElementById("start-relapse");
const firmwareStatus = document.getElementById("firmware-status");
const consoleOutput = document.getElementById("console");
const dumpModeControl = document.getElementById("dump-mode");
window.__relapseMode = "relapse";
window.__relapseCleanupFailed = false;

if (window.firmware) {
  const rejection = window.firmware.rejection();
  if (rejection) {
    firmwareStatus.textContent = `${rejection}. Confirm the installed system software in Settings before starting.`;
    firmwareStatus.classList.add("error");
  } else if (window.fw_str !== "13.60") {
    firmwareStatus.textContent = `This HV package is pinned to 13.60. The browser reports ${window.fw_str}; check Console Information in Settings before proceeding.`;
    firmwareStatus.classList.add("error");
  } else {
    firmwareStatus.textContent = "Browser reports PS5 firmware 13.60. Confirm Console Information in Settings, then choose a Relapse mode.";
    firmwareStatus.classList.add("ready");
    startButton.disabled = false;
  }
} else {
  const reported = (navigator.userAgent.match(/PlayStation 5\/(\d+\.\d+)/) || [])[1];
  if (reported === "13.60") {
    window.fw_str = reported;
    firmwareStatus.textContent = "Console reports firmware 13.60. The firmware check script did not load; reload this page before starting.";
  } else {
    firmwareStatus.textContent = "Could not verify firmware 13.60. Reload this page before starting.";
  }
  firmwareStatus.classList.add("error");
}

startButton.addEventListener("click", async () => {
  if (startButton.disabled) return;
  const rejection = window.firmware?.rejection();
  if (!window.firmware || rejection || window.fw_str !== "13.60") {
    firmwareStatus.textContent = !window.firmware
      ? "The upstream firmware check did not load. Check the page connection and reload before trying again."
      : rejection || `This page is for firmware 13.60; the browser reports ${window.fw_str || "an unknown version"}.`;
    firmwareStatus.classList.add("error");
    return;
  }
  const dumpMode = Boolean(dumpModeControl && dumpModeControl.checked);
  window.__relapseMode = dumpMode ? "dump" : "relapse";
  if (dumpModeControl) dumpModeControl.disabled = true;
  startButton.disabled = true;
  consoleOutput.textContent = "Loading upstream Relapse…\n";
  window.__relapseDiagnostics?.log("Start Relapse selected", "info");
  try {
    if (window.__relapseOffsetsReady) {
      consoleOutput.textContent += "Waiting for firmware offsets…\n";
      await window.__relapseOffsetsReady;
      window.__relapseDiagnostics?.log("Firmware offsets loaded", "info");
    } else {
      throw new Error("Firmware offset loader did not initialize. Reload this page.");
    }
    const { runRelapse } = await import("./src/site.js");
    const result = await runRelapse();
    if (!result || !result.done || !result.payloads || window.__relapseCleanupFailed) {
      throw new Error("Relapse did not confirm payload loading and cleanup. Restart the console before another attempt.");
    }
    const diagnostics = window.__relapseDiagnostics;
    if (!dumpMode && (!diagnostics || !diagnostics.log("Relapse cleanup complete; HV delivery ready.", "success"))) {
      throw new Error("Relapse finished, but the server did not acknowledge the completion message. Do not start another exploit in this boot.");
    }
    if (diagnostics) await diagnostics.drain();
    if (dumpMode) {
      firmwareStatus.textContent = "Relapse and selected dumps are complete; temporary exploit state was restored. Do not start another run in this boot.";
    } else {
      firmwareStatus.textContent = "Relapse completed and temporary exploit state was restored. This does not confirm a hypervisor bypass. Do not start another run in this boot.";
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    consoleOutput.textContent += `\n[page] ${message}`;
    window.__relapseDiagnostics?.log(`[page] ${message}`, "error");
    firmwareStatus.textContent = message;
    firmwareStatus.classList.add("error");
  } finally {
    if (dumpModeControl) dumpModeControl.disabled = true;
  }
});
