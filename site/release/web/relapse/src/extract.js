// Manual, conservative kernel extraction for PS5 FW 13.60.
// Runs while Relapse's pipe-backed R/W is live and pauses for user clicks.
"use strict";

const CONFIG = {
  RECEIVER: "../../dump",
  READ_CHUNK: 0x1000,
  READ_DELAY_MS: 100,
  SYSENT_RVA: 0xE6E5C0,
  SYSENT_COUNT: 679,
  SYSENT_ENTRY_SIZE: 48,
};

function hex(n) { return "0x" + n.toString(16); }
function i64ToBig(v) { return (BigInt(v.hi >>> 0) << 32n) | BigInt(v.low >>> 0); }
function bigToI64(kexp, b) {
  const Ctor = kexp.kbase.constructor;
  return new Ctor(Number(b & 0xffffffffn), Number((b >> 32n) & 0xffffffffn));
}
function delay(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

async function postDump(filename, data, chunk) {
  const sessionId = window.__relapseDiagnostics?.sessionId;
  if (!sessionId) throw new Error("Missing this run’s dump session ID; reload before starting Relapse.");
  const headers = { "X-Filename": filename, "X-Session": sessionId };
  if (chunk) headers["X-Chunk"] = `${chunk.index}/${chunk.total}`;
  const receiver = new URL(CONFIG.RECEIVER, import.meta.url);
  const response = await fetch(receiver, {
    method: "POST",
    headers,
    body: data,
  });
  if (!response.ok) throw new Error(`POST ${filename}: HTTP ${response.status}`);
  return response.json();
}

async function kread(kexp, address, length) {
  const buffer = kexp.p.malloc(length, 1);
  const read = await kexp.kreadFast(address, length, buffer);
  if (read !== length) return null;
  return buffer.backing.subarray(0, length);
}

function updateProgress(progress, status, value, max, message) {
  progress.max = Math.max(1, max);
  progress.value = value;
  status.textContent = message;
}

async function dumpKernelBase(kexp) {
  const base = i64ToBig(kexp.kbase);
  const data = new TextEncoder().encode(JSON.stringify({
    kernel_base: base,
    firmware: "13.60",
  }, (key, value) => typeof value === "bigint" ? hex(value) : value, 2));
  await postDump("kernel_base.json", data);
}

async function dumpSysent(kexp, log, progress, status) {
  const base = i64ToBig(kexp.kbase);
  const tableAddress = base + BigInt(CONFIG.SYSENT_RVA);
  const tableSize = CONFIG.SYSENT_COUNT * CONFIG.SYSENT_ENTRY_SIZE;
  const totalChunks = Math.ceil(tableSize / CONFIG.READ_CHUNK);
  let completed = 0;

  for (let index = 0; index < totalChunks; index++) {
    const length = Math.min(CONFIG.READ_CHUNK, tableSize - completed);
    const address = bigToI64(kexp, tableAddress + BigInt(completed));
    const part = await kread(kexp, address, length);
    if (!part) throw new Error(`sysent read fault at +${hex(BigInt(completed))}`);

    // Send each piece immediately so a later crash still leaves partial data.
    await postDump("sysent_raw.bin", part, { index: index + 1, total: totalChunks });
    completed += length;

    const current = index + 1;
    updateProgress(progress, status, current, totalChunks,
      `Sysent: ${current}/${totalChunks} reads; ${completed}/${tableSize} bytes received.`);
    log(`sysent chunk ${current}/${totalChunks} posted (${completed}/${tableSize} bytes)`);

    if (current < totalChunks) await delay(CONFIG.READ_DELAY_MS);
  }

  return true;
}

export async function runExtraction(kexp, log) {
  const panel = document.getElementById("dump-controls");
  const baseButton = document.getElementById("dump-kernel-base");
  const sysentButton = document.getElementById("dump-sysent");
  const finishButton = document.getElementById("finish-dumps");
  const progress = document.getElementById("dump-progress");
  const status = document.getElementById("dump-progress-text");
  if (!panel || !baseButton || !sysentButton || !finishButton || !progress || !status)
    throw new Error("manual dump controls are missing from the page");

  panel.hidden = false;
  baseButton.disabled = false;
  finishButton.disabled = false;
  progress.max = Math.ceil((CONFIG.SYSENT_COUNT * CONFIG.SYSENT_ENTRY_SIZE) / CONFIG.READ_CHUNK);
  progress.value = 0;
  status.textContent = "Ready. No kernel reads have run. Choose one dump, then finish and restore.";
  log(`manual controls ready; sysent uses ${CONFIG.READ_CHUNK}-byte reads with ${CONFIG.READ_DELAY_MS} ms pauses`);

  await new Promise((resolve) => {
    let finished = false;
    let busy = false;
    let baseDone = false;

    const setBusy = (value) => {
      busy = value;
      baseButton.disabled = busy || baseDone;
      sysentButton.disabled = busy || !baseDone;
      finishButton.disabled = busy;
    };

    baseButton.addEventListener("click", async () => {
      if (busy || baseDone) return;
      setBusy(true);
      updateProgress(progress, status, 0, 1, "Saving kernel base…");
      try {
        await dumpKernelBase(kexp);
        baseDone = true;
        updateProgress(progress, status, 1, 1, "Kernel base saved. Sysent is ready when you choose it.");
        log("posted kernel_base.json");
      } catch (error) {
        updateProgress(progress, status, 0, 1, `Kernel base failed: ${String(error.message || error)}`);
        log(`kernel base failed: ${String(error.message || error)}`);
      } finally {
        setBusy(false);
      }
    });

    sysentButton.addEventListener("click", async () => {
      if (busy || !baseDone) return;
      setBusy(true);
      progress.value = 0;
      progress.max = Math.ceil((CONFIG.SYSENT_COUNT * CONFIG.SYSENT_ENTRY_SIZE) / CONFIG.READ_CHUNK);
      status.textContent = "Starting sysent read…";
      try {
        await dumpSysent(kexp, log, progress, status);
        sysentButton.disabled = true;
        updateProgress(progress, status, progress.max, progress.max, "Sysent table saved; the server is preparing the parsed index.");
        log("sysent extraction complete");
        void refreshDumpResults(status);
      } catch (error) {
        status.textContent = `Sysent stopped: ${String(error.message || error)}. Partial raw chunks, if any, remain saved.`;
        log(`sysent failed: ${String(error.message || error)}`);
      } finally {
        busy = false;
        baseButton.disabled = true;
        sysentButton.disabled = !baseDone || status.textContent.startsWith("Sysent table saved;");
        finishButton.disabled = false;
      }
    });

    finishButton.addEventListener("click", () => {
      if (busy || finished) return;
      finished = true;
      panel.hidden = true;
      log("manual dump session finished; restoring exploit state");
      resolve();
    }, { once: true });
  });
}

async function refreshDumpResults(status) {
  const results = document.getElementById("dump-results");
  const sessionId = window.__relapseDiagnostics?.sessionId;
  if (!results || !sessionId) return;
  try {
    const statusUrl = new URL(`../../api/dump/status?session_id=${encodeURIComponent(sessionId)}`, import.meta.url);
    const response = await fetch(statusUrl, { credentials: "same-origin" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const state = await response.json();
    results.replaceChildren();
    for (const file of state.files || []) {
      const link = document.createElement("a");
      link.href = new URL(`../../api/dump/${encodeURIComponent(sessionId)}/${encodeURIComponent(file.name)}`, import.meta.url).toString();
      link.download = file.name;
      link.textContent = `Download ${file.name} (${file.bytes.toLocaleString()} bytes)`;
      results.appendChild(link);
    }
    if (state.complete) status.textContent = "Sysent table and parsed index are ready to download.";
    else if (!state.files?.some(file => file.name === "sysent_raw.bin")) {
      status.textContent = "Sysent chunks saved, but the complete parsed index is not yet ready.";
    }
  } catch (error) {
    status.textContent += ` Files were received, but status check failed: ${String(error.message || error)}`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const results = document.getElementById("dump-results");
  if (!results) return;
  results.addEventListener("click", async (event) => {
    const link = event.target.closest("a");
    if (!link) return;
    event.preventDefault();
    try {
      const response = await fetch(link.href, { credentials: "same-origin" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const blob = await response.blob();
      const local = document.createElement("a");
      local.href = URL.createObjectURL(blob);
      local.download = link.download;
      local.click();
      URL.revokeObjectURL(local.href);
    } catch (error) {
      document.getElementById("dump-progress-text").textContent = `Download failed: ${String(error.message || error)}`;
    }
  });
});
