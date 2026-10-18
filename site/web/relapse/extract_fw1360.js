"use strict";

// Adapter for Relapse's live KernelExploit instance. Call from run() before
// rescue() closes the pipe-backed kernel read/write primitive.
export async function runFw1360Extraction(kexp, log = (m) => print(`[dump] ${m}`)) {
  for (const name of ["kreadFast", "readKernel32", "readKernel64"]) {
    if (!kexp || typeof kexp[name] !== "function")
      throw new Error(`Relapse kernel R/W API missing ${name}`);
  }
  if (!kexp.kbase || !kexp.p || typeof kexp.p.malloc !== "function")
    throw new Error("Relapse kernel base or allocator is unavailable");

  const { runExtraction } = await import("./src/extract.js");
  return runExtraction(kexp, log);
}
