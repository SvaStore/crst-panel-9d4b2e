/* Crast key + account core. Runs in the browser and in Node for testing. */
(function (root) {
  "use strict";

  const MASK = (1n << 64n) - 1n;
  const ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
  const PEPPER = "|CrastSealKey2026";
  const MASTER_TEXT = "CrastSeal/v2|accounts|2026";

  const rotl = (value, bits) =>
    ((value << BigInt(bits)) | (value >> BigInt(64 - bits))) & MASK;

  const u64 = (bytes, offset) => {
    let value = 0n;
    for (let i = 7; i >= 0; --i) value = (value << 8n) | BigInt(bytes[offset + i]);
    return value;
  };

  const putU64 = (bytes, offset, value) => {
    for (let i = 0; i < 8; ++i) {
      bytes[offset + i] = Number(value & 0xffn);
      value >>= 8n;
    }
  };

  const hex16 = value => value.toString(16).padStart(16, "0");

  function fnv(text) {
    let hash = 0xCBF29CE484222325n;
    for (let i = 0; i < text.length; ++i) {
      hash ^= BigInt(text.charCodeAt(i));
      hash = (hash * 0x100000001B3n) & MASK;
      hash = rotl(hash, 27);
    }
    return hash;
  }

  function hashPassword(user, pass) {
    const salt = "CrastSeal|" + user.toLowerCase() + "|" + pass;
    let a = fnv(salt + "|A");
    let b = fnv(salt + "|B");
    for (let round = 0; round < 4096; ++round) {
      a = (rotl(a ^ ((BigInt(round) * 0x9E3779B97F4A7C15n) & MASK), 29)
           * 0xBF58476D1CE4E5B9n) & MASK;
      b = (rotl((b + a) & MASK, 31) ^ 0x94D049BB133111EBn) & MASK;
    }
    return hex16(a) + hex16(b);
  }

  async function sha256(bytes) {
    const subtle = (root.crypto && root.crypto.subtle) ||
      (typeof require === "function" ? require("crypto").webcrypto.subtle : null);
    if (subtle) {
      try { return new Uint8Array(await subtle.digest("SHA-256", bytes)); }
      catch { }
    }
    return sha256Fallback(bytes);
  }

  /* Pure-JS SHA-256 fallback for file:// and older browsers where
   * crypto.subtle is missing. It must match the loader's .NET SHA-256. */
  function sha256Fallback(bytes) {
    const K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    const H = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];
    const rotr = (value, bits) => ((value >>> bits) | (value << (32 - bits))) >>> 0;
    const length = bytes.length;
    const padded = new Uint8Array((((length + 9) + 63) >> 6) << 6);
    padded.set(bytes);
    padded[length] = 0x80;
    const view = new DataView(padded.buffer);
    const bits = length * 8;
    view.setUint32(padded.length - 8, Math.floor(bits / 0x100000000));
    view.setUint32(padded.length - 4, bits >>> 0);
    const w = new Uint32Array(64);
    for (let offset = 0; offset < padded.length; offset += 64) {
      for (let i = 0; i < 16; ++i) w[i] = view.getUint32(offset + i * 4);
      for (let i = 16; i < 64; ++i) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; ++i) {
        const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + s1 + ch + K[i] + w[i]) >>> 0;
        const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (s0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer);
    for (let i = 0; i < 8; ++i) outView.setUint32(i * 4, H[i]);
    return out;
  }

  function randomBytes(length) {
    const out = new Uint8Array(length);
    if (root.crypto && root.crypto.getRandomValues)
      root.crypto.getRandomValues(out);
    else
      for (let i = 0; i < out.length; ++i)
        out[i] = Math.floor(Math.random() * 256);
    return out;
  }

  const utf8 = text => new TextEncoder().encode(text);

  function concat(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  async function purpose(name) {
    const master = await sha256(utf8(MASTER_TEXT));
    return sha256(concat(master, utf8("|" + name)));
  }

  function next(state) {
    state.s0 = (state.s0 + 0x9E3779B97F4A7C15n) & MASK;
    state.s0 = rotl(state.s0, 27);
    state.s0 ^= state.s1;
    state.s1 = (rotl(state.s1, 31) + state.s0) & MASK;
    state.s1 ^= 0xD1B54A32D192ED03n;
    return state.s0 ^ state.s1;
  }

  function xor(data, key, nonce) {
    const state = {
      s0: u64(key, 0) ^ u64(nonce, 0),
      s1: u64(key, 8) ^ u64(nonce, 4)
    };
    for (let offset = 0; offset < data.length; offset += 8) {
      let block = next(state);
      const count = Math.min(8, data.length - offset);
      for (let i = 0; i < count; ++i) {
        data[offset + i] ^= Number(block & 0xffn);
        block >>= 8n;
      }
    }
  }

  function tag(key, nonce, body) {
    let a = u64(key, 0) ^ 0x6A09E667F3BCC909n;
    let b = u64(key, 8) ^ 0xBB67AE8584CAA73Bn;
    for (const value of nonce) {
      a = ((a ^ BigInt(value)) * 0x100000001B3n) & MASK;
      a = rotl(a, 23);
      b = (b + a) & MASK;
      b = rotl(b, 17);
    }
    for (const value of body) {
      a = ((a ^ BigInt(value)) * 0x100000001B3n) & MASK;
      a = rotl(a, 29);
      b = ((b + a) & MASK) ^ 0x9E3779B97F4A7C15n;
      b = rotl(b, 13);
    }
    a ^= b;
    b = rotl(b, 41);
    a = ((a + b) * 0xBF58476D1CE4E5B9n) & MASK;
    const out = new Uint8Array(16);
    putU64(out, 0, a);
    putU64(out, 8, b);
    return out;
  }

  async function seal(plain, name) {
    const key = await purpose(name);
    const nonce = randomBytes(12);
    const cipher = new Uint8Array(plain);
    xor(cipher, key, nonce);
    const check = tag(key, nonce, cipher);
    const blob = new Uint8Array(28 + cipher.length);
    blob.set(nonce, 0);
    blob.set(check, 12);
    blob.set(cipher, 28);
    return blob;
  }

  async function unseal(blob, name) {
    if (!blob || blob.length < 28) return null;
    const key = await purpose(name);
    const nonce = blob.slice(0, 12);
    const check = blob.subarray(12, 28);
    const cipher = blob.slice(28);
    const calculated = tag(key, nonce, cipher);
    for (let i = 0; i < 16; ++i)
      if (calculated[i] !== check[i]) return null;
    xor(cipher, key, nonce);
    return cipher;
  }

  function normalize(input) {
    if (!input) return "";
    return input.toUpperCase().replace(/[^A-Z0-9]/g, "");
  }

  function checksum(body) {
    let hash = 0x6D2B79F5 >>> 0;
    const text = body + PEPPER;
    for (let i = 0; i < text.length; ++i) {
      hash = (hash ^ Math.imul(text.charCodeAt(i), 0x9E3779B1)) >>> 0;
      hash = ((hash << 13) | (hash >>> 19)) >>> 0;
      hash = (hash + 0x7F4A7C15) >>> 0;
    }
    hash = (hash ^ (hash >>> 16)) >>> 0;
    hash = Math.imul(hash, 0x85EBCA6B) >>> 0;
    hash = (hash ^ (hash >>> 13)) >>> 0;
    hash = Math.imul(hash, 0xC2B2AE35) >>> 0;
    hash = (hash ^ (hash >>> 16)) >>> 0;
    let out = "";
    for (let i = 0; i < 5; ++i) {
      out += ALPHABET[hash & 31];
      hash >>>= 5;
    }
    return out;
  }

  function format(raw) {
    if (raw.length !== 24) return raw;
    return raw.slice(0, 4) + "-" + raw.slice(4, 9) + "-" + raw.slice(9, 14) +
      "-" + raw.slice(14, 19) + "-" + raw.slice(19, 24);
  }

  function validKey(input) {
    const raw = normalize(input);
    if (raw.length !== 24 || !raw.startsWith("CRST")) return false;
    for (let i = 4; i < raw.length; ++i)
      if (ALPHABET.indexOf(raw[i]) < 0) return false;
    return checksum(raw.slice(4, 19)) === raw.slice(19, 24);
  }

  function makeKey() {
    const bytes = randomBytes(15);
    let body = "";
    for (const byte of bytes) body += ALPHABET[byte & 31];
    return format("CRST" + body + checksum(body));
  }

  async function buildStore(accounts) {
    const text = accounts.map(account =>
      account.user + "\t" + account.hash + "\t" + (account.key || "") + "\t" +
      account.created + "\t" + (account.hwid || "").toUpperCase() + "\t" +
      (account.flags || 0)).join("\n") + "\n";
    return seal(utf8(text), "accounts");
  }

  async function buildBlacklist(entries) {
    const text = entries.map(entry =>
      (entry.hwid || "").toUpperCase() + "\t" + (entry.user || "") + "\t" +
      (entry.reason || "") + "\t" + (entry.time || Math.floor(Date.now() / 1000)) +
      "\t" + (entry.token || "").toUpperCase()).join("\n") + "\n";
    return seal(utf8(text), "blacklist");
  }

  function validHwid(value) {
    return /^[0-9a-f]{16}$/i.test(value || "");
  }

  function toHex(blob) {
    return Array.from(blob, value => value.toString(16).padStart(2, "0")).join("");
  }

  function toReg(blob, blacklist) {
    const hex = Array.from(blob, value => value.toString(16).padStart(2, "0")).join(",");
    let out = "Windows Registry Editor Version 5.00\r\n\r\n" +
      "[HKEY_CURRENT_USER\\Software\\CrastRobRun\\Accounts]\r\n" +
      "\"Store\"=hex:" + hex + "\r\n";
    if (blacklist && blacklist.length) {
      const black = Array.from(blacklist, value => value.toString(16).padStart(2, "0")).join(",");
      out += "\r\n[HKEY_CURRENT_USER\\Software\\CrastRobRun\\Blacklist]\r\n" +
        "\"List\"=hex:" + black + "\r\n";
    }
    return out;
  }

  root.CrastCore = {
    ALPHABET, normalize, format, validKey, makeKey, checksum, validHwid,
    hashPassword, buildStore, buildBlacklist, toHex, toReg, seal, unseal, purpose, utf8,
    sha256Fallback, randomBytes
  };
})(typeof window !== "undefined" ? window : globalThis);

if (typeof module !== "undefined" && module.exports) module.exports = globalThis.CrastCore;
