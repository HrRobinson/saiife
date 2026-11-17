// The device key: IndexedDB "saiife-workspace", store "keys", one record
// "device" = {key: CryptoKey (private, not extractable), publicRaw:
// Uint8Array(65), deviceId, machineId}. No DOM.

const DB = "saiife-workspace";
const STORE = "keys";
const ID = "device";

function valid(rec) {
  return (
    rec !== null &&
    typeof rec === "object" &&
    rec.key !== null &&
    typeof rec.key === "object" &&
    rec.publicRaw instanceof Uint8Array &&
    rec.publicRaw.length === 65 &&
    typeof rec.deviceId === "string" &&
    typeof rec.machineId === "string"
  );
}

function open() {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") return reject(new Error("no IndexedDB"));
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
    req.onblocked = () => reject(new Error("IndexedDB blocked"));
  });
}

// One request in one transaction; resolves when the transaction completes.
async function run(mode, fn) {
  const db = await open();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const req = fn(tx.objectStore(STORE));
      tx.oncomplete = () => resolve(req.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error ?? new Error("aborted"));
    });
  } finally {
    db.close();
  }
}

// The record, or null when absent, malformed or IndexedDB is unavailable.
export async function loadDevice() {
  try {
    const rec = await run("readonly", (s) => s.get(ID));
    return valid(rec) ? rec : null;
  } catch {
    return null;
  }
}

export async function saveDevice(rec) {
  if (!valid(rec)) throw new Error("not a device record");
  await run("readwrite", (s) => s.put(rec, ID));
}

export async function forgetDevice() {
  await run("readwrite", (s) => s.delete(ID));
}

// The same API in memory, for node tests.
export function memoryStore() {
  let rec = null;
  return {
    async loadDevice() {
      return rec;
    },
    async saveDevice(r) {
      if (!valid(r)) throw new Error("not a device record");
      rec = r;
    },
    async forgetDevice() {
      rec = null;
    },
  };
}
