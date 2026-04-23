/**
 * base64url encoding helpers — works in Node, Cloudflare Workers, and browsers.
 *
 * Avoids depending on Node's Buffer so the SDK runs anywhere.
 */

const STD_TO_URL = { "+": "-", "/": "_" };
const URL_TO_STD = { "-": "+", _: "/" };

function bytesToBase64(bytes) {
  // btoa is available in Workers and browsers; in Node 20+ it's a global too.
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function base64ToBytes(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function b64urlEncode(input) {
  let bytes;
  if (typeof input === "string") {
    bytes = new TextEncoder().encode(input);
  } else if (input instanceof Uint8Array) {
    bytes = input;
  } else if (input instanceof ArrayBuffer) {
    bytes = new Uint8Array(input);
  } else {
    throw new TypeError("b64urlEncode: input must be string, Uint8Array, or ArrayBuffer");
  }
  const b64 = bytesToBase64(bytes);
  return b64.replace(/[+/]/g, (c) => STD_TO_URL[c]).replace(/=+$/g, "");
}

export function b64urlDecode(s) {
  const padded = s.replace(/[-_]/g, (c) => URL_TO_STD[c]) + "=".repeat((4 - (s.length % 4)) % 4);
  return base64ToBytes(padded);
}

export function b64urlDecodeString(s) {
  return new TextDecoder().decode(b64urlDecode(s));
}
