"use strict";

const startButton = document.getElementById("start-relapse");
const firmwareStatus = document.getElementById("firmware-status");
const consoleOutput = document.getElementById("console");

if (window.firmware) {
  const rejection = window.firmware.rejection();
  if (rejection) {
    firmwareStatus.textContent = `${rejection}. Confirm the installed system software in Settings before starting.`;
    firmwareStatus.classList.add("error");
  } else if (window.fw_str !== "13.60") {
    firmwareStatus.textContent = `This HV package is pinned to 13.60. The browser reports ${window.fw_str}; check Console Information in Settings before proceeding.`;
    firmwareStatus.classList.add("error");
  } else {
    firmwareStatus.textContent = "Browser reports PS5 firmware 13.60. Confirm Console Information in Settings, then choose Start Relapse.";
    firmwareStatus.classList.add("ready");
    startButton.disabled = false;
  }
} else {
  firmwareStatus.textContent = "Could not load the firmware check. Reload this page before starting.";
  firmwareStatus.classList.add("error");
}

startButton.addEventListener("click", async () => {
  if (startButton.disabled) return;
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
    await import("./src/site.js");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    consoleOutput.textContent += `\n[page] ${message}`;
    window.__relapseDiagnostics?.log(`[page] ${message}`, "error");
    firmwareStatus.textContent = "Relapse could not start. Read the page output before reloading.";
    firmwareStatus.classList.add("error");
    startButton.disabled = false;
  }
});
