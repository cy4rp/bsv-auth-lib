import { describe, it, expect } from "vitest";
import { base58check } from "../base58check.js";

describe("base58check", () => {
  it("encode-then-decode round-trips", () => {
    const payload = new Uint8Array([0xef, 0x01, 0x02, 0x03, 0x04]);
    const encoded = base58check.encode(payload);
    const decoded = base58check.decode(encoded);
    expect(Array.from(decoded)).toEqual(Array.from(payload));
  });

  it("rejects corrupted data", () => {
    const payload = new Uint8Array([0x00, 0xaa, 0xbb, 0xcc]);
    const encoded = base58check.encode(payload);
    // Flip a character
    const chars = encoded.split("");
    const idx = Math.floor(chars.length / 2);
    chars[idx] = chars[idx] === "A" ? "B" : "A";
    expect(() => base58check.decode(chars.join(""))).toThrow();
  });

  it("handles leading zero bytes", () => {
    const payload = new Uint8Array([0x00, 0x00, 0x01, 0x02]);
    const encoded = base58check.encode(payload);
    expect(encoded.startsWith("1")).toBe(true); // leading zeros → leading '1's
    const decoded = base58check.decode(encoded);
    expect(Array.from(decoded)).toEqual(Array.from(payload));
  });

  it("rejects too-short input", () => {
    expect(() => base58check.decode("1")).toThrow();
  });
});
