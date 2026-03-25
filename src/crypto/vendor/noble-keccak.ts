/**
 * Vendored from @noble/hashes v1.8.0
 * Source: https://github.com/paulmillr/noble-hashes
 * License: MIT
 *
 * Only keccak_256 and bytesToHex are used by MOCI.
 * Vendored to eliminate supply chain risk.
 *
 * Sources merged from:
 *   - src/_u64.ts  (u64 arithmetic helpers)
 *   - src/utils.ts (hash primitives and byte utilities)
 *   - src/sha3.ts  (Keccak sponge construction)
 */

// ---------------------------------------------------------------------------
// _u64.ts — 64-bit arithmetic via paired Uint32Array (high/low words)
// ---------------------------------------------------------------------------

const U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
const _32n = /* @__PURE__ */ BigInt(32);

function fromBig(n: bigint, le = false): { h: number; l: number } {
  if (le) return { h: Number(n & U32_MASK64), l: Number((n >> _32n) & U32_MASK64) };
  return { h: Number((n >> _32n) & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}

function split(lst: bigint[], le = false): Uint32Array[] {
  const len = lst.length;
  const Ah = new Uint32Array(len);
  const Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}

// Left rotate for shift in [1, 32)
const rotlSH = (h: number, l: number, s: number): number => (h << s) | (l >>> (32 - s));
const rotlSL = (h: number, l: number, s: number): number => (l << s) | (h >>> (32 - s));
// Left rotate for shift in (32, 64)
const rotlBH = (h: number, l: number, s: number): number => (l << (s - 32)) | (h >>> (64 - s));
const rotlBL = (h: number, l: number, s: number): number => (h << (s - 32)) | (l >>> (64 - s));

// ---------------------------------------------------------------------------
// utils.ts — byte utilities and abstract Hash infrastructure
// ---------------------------------------------------------------------------

/** Generic type for 8/16/32-bit typed arrays (not 64-bit). */
export type TypedArray =
  | Int8Array
  | Uint8ClampedArray
  | Uint8Array
  | Uint16Array
  | Int16Array
  | Uint32Array
  | Int32Array;

/** Accepted input for hash functions. */
export type Input = string | Uint8Array;

/** Checks whether a value is a Uint8Array (Node.js Buffer also returns true). */
export function isBytes(a: unknown): a is Uint8Array {
  return (
    a instanceof Uint8Array ||
    (ArrayBuffer.isView(a) && (a as { constructor: { name: string } }).constructor.name === 'Uint8Array')
  );
}

/** Asserts that n is a non-negative safe integer. */
export function anumber(n: number): void {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('positive integer expected, got ' + n);
}

/** Asserts that b is a Uint8Array, optionally verifying its length. */
export function abytes(b: Uint8Array | undefined, ...lengths: number[]): void {
  if (!isBytes(b)) throw new Error('Uint8Array expected');
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error('Uint8Array expected of length ' + lengths + ', got length=' + b.length);
}

/** Asserts that a hash instance has not been destroyed or finalized. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function aexists(instance: any, checkFinished = true): void {
  if (instance.destroyed) throw new Error('Hash instance has been destroyed');
  if (checkFinished && instance.finished) throw new Error('Hash#digest() has already been called');
}

/** Asserts that the output buffer is at least as large as the hash output. */
export function aoutput(out: Uint8Array, instance: { outputLen: number }): void {
  abytes(out);
  const min = instance.outputLen;
  if (out.length < min)
    throw new Error('digestInto() expects output buffer of length at least ' + min);
}

/** Casts a typed array view to Uint32Array sharing the same buffer. */
export function u32(arr: TypedArray): Uint32Array {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}

/** Zeroes one or more typed arrays. */
export function clean(...arrays: TypedArray[]): void {
  for (let i = 0; i < arrays.length; i++) arrays[i].fill(0);
}

/** True when the host platform is little-endian (the common case). */
export const isLE: boolean = /* @__PURE__ */ (() =>
  new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44)();

/** Byte-swaps a uint32. */
function byteSwap(word: number): number {
  return (
    ((word << 24) & 0xff000000) |
    ((word << 8) & 0xff0000) |
    ((word >>> 8) & 0xff00) |
    ((word >>> 24) & 0xff)
  );
}

/** In-place byte-swap of every element in a Uint32Array. */
function byteSwap32(arr: Uint32Array): Uint32Array {
  for (let i = 0; i < arr.length; i++) arr[i] = byteSwap(arr[i]);
  return arr;
}

/** Byte-swaps a Uint32Array only on big-endian platforms; no-op on little-endian. */
export const swap32IfBE: (u: Uint32Array) => Uint32Array = isLE ? (u) => u : byteSwap32;

/** Encodes a string to UTF-8 bytes. */
function utf8ToBytes(str: string): Uint8Array {
  if (typeof str !== 'string') throw new Error('string expected');
  return new Uint8Array(new TextEncoder().encode(str));
}

/** Normalises a string or Uint8Array input to Uint8Array. */
export function toBytes(data: Input): Uint8Array {
  if (typeof data === 'string') data = utf8ToBytes(data);
  abytes(data as Uint8Array);
  return data as Uint8Array;
}

/** Abstract base class that every hash implementation extends. */
export abstract class Hash<T extends Hash<T>> {
  abstract blockLen: number;
  abstract outputLen: number;
  abstract update(buf: Input): this;
  abstract digestInto(buf: Uint8Array): void;
  abstract digest(): Uint8Array;
  abstract destroy(): void;
  abstract _cloneInto(to?: T): T;
  abstract clone(): T;
}

/** Streaming XOF interface (used only for type annotation on Keccak). */
export type HashXOF<T extends Hash<T>> = Hash<T> & {
  xof(bytes: number): Uint8Array;
  xofInto(buf: Uint8Array): Uint8Array;
};

/** The callable type produced by createHasher. */
export type CHash = {
  (msg: Input): Uint8Array;
  outputLen: number;
  blockLen: number;
  create(): Hash<Hash<never>>;
};

/** Wraps a hash constructor into a callable function with metadata properties. */
export function createHasher<T extends Hash<T>>(
  hashCons: () => Hash<T>
): CHash {
  const hashC = (msg: Input): Uint8Array => hashCons().update(toBytes(msg)).digest();
  const tmp = hashCons();
  (hashC as unknown as { outputLen: number }).outputLen = tmp.outputLen;
  (hashC as unknown as { blockLen: number }).blockLen = tmp.blockLen;
  (hashC as unknown as { create: () => Hash<T> }).create = () => hashCons();
  return hashC as unknown as CHash;
}

// True when the JS engine exposes the native Uint8Array.toHex / fromHex builtins.
const hasHexBuiltin: boolean = /* @__PURE__ */ (() =>
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  typeof (Uint8Array.from([]) as any).toHex === 'function' &&
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  typeof (Uint8Array as any).fromHex === 'function')();

// Lookup table: index 0xf0 maps to the string 'f0'.
const hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) =>
  i.toString(16).padStart(2, '0')
);

/**
 * Convert a byte array to a lowercase hex string.
 * Uses the native built-in when available (Node.js ≥ 22).
 *
 * @param bytes - The bytes to encode.
 * @returns Lowercase hexadecimal string.
 * @example bytesToHex(Uint8Array.from([0xca, 0xfe])) // 'cafe'
 */
export function bytesToHex(bytes: Uint8Array): string {
  abytes(bytes);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  if (hasHexBuiltin) return (bytes as any).toHex() as string;
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += hexes[bytes[i]];
  return hex;
}

// ---------------------------------------------------------------------------
// sha3.ts — Keccak-f[1600] permutation and keccak_256 hash function
// ---------------------------------------------------------------------------

// Per-round constants (computed once at module load).
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _7n = BigInt(7);
const _256n = BigInt(256);
const _0x71n = BigInt(0x71);

const SHA3_PI: number[] = [];
const SHA3_ROTL: number[] = [];
const _SHA3_IOTA: bigint[] = [];

for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
  [x, y] = [y, (2 * x + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x));
  SHA3_ROTL.push((((round + 1) * (round + 2)) / 2) % 64);
  let t = _0n;
  for (let j = 0; j < 7; j++) {
    R = ((R << _1n) ^ ((R >> _7n) * _0x71n)) % _256n;
    if (R & _2n) t ^= _1n << ((_1n << /* @__PURE__ */ BigInt(j)) - _1n);
  }
  _SHA3_IOTA.push(t);
}

const IOTAS = split(_SHA3_IOTA, true);
const SHA3_IOTA_H = IOTAS[0];
const SHA3_IOTA_L = IOTAS[1];

// Dispatch rotation helpers by shift magnitude.
const rotlH = (h: number, l: number, s: number): number =>
  s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
const rotlL = (h: number, l: number, s: number): number =>
  s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);

/**
 * keccak-f[1600] permutation.
 * Operates on a 50-element Uint32Array representing 25 × 64-bit lanes.
 *
 * @param s      - State array (50 uint32 values, modified in place).
 * @param rounds - Number of rounds to apply (default 24).
 */
export function keccakP(s: Uint32Array, rounds = 24): void {
  const B = new Uint32Array(5 * 2);
  for (let round = 24 - rounds; round < 24; round++) {
    // Theta θ
    for (let x = 0; x < 10; x++) B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
    for (let x = 0; x < 10; x += 2) {
      const idx1 = (x + 8) % 10;
      const idx0 = (x + 2) % 10;
      const B0 = B[idx0];
      const B1 = B[idx0 + 1];
      const Th = rotlH(B0, B1, 1) ^ B[idx1];
      const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
      for (let y = 0; y < 50; y += 10) {
        s[x + y] ^= Th;
        s[x + y + 1] ^= Tl;
      }
    }
    // Rho (ρ) and Pi (π)
    let curH = s[2];
    let curL = s[3];
    for (let t = 0; t < 24; t++) {
      const shift = SHA3_ROTL[t];
      const Th = rotlH(curH, curL, shift);
      const Tl = rotlL(curH, curL, shift);
      const PI = SHA3_PI[t];
      curH = s[PI];
      curL = s[PI + 1];
      s[PI] = Th;
      s[PI + 1] = Tl;
    }
    // Chi (χ)
    for (let y = 0; y < 50; y += 10) {
      for (let x = 0; x < 10; x++) B[x] = s[y + x];
      for (let x = 0; x < 10; x++) s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
    }
    // Iota (ι)
    s[0] ^= SHA3_IOTA_H[round];
    s[1] ^= SHA3_IOTA_L[round];
  }
  clean(B);
}

/** Keccak sponge construction. */
export class Keccak extends Hash<Keccak> implements HashXOF<Keccak> {
  protected state: Uint8Array;
  protected pos = 0;
  protected posOut = 0;
  protected finished = false;
  protected state32: Uint32Array;
  protected destroyed = false;

  public blockLen: number;
  public suffix: number;
  public outputLen: number;
  protected enableXOF: boolean;
  protected rounds: number;

  constructor(
    blockLen: number,
    suffix: number,
    outputLen: number,
    enableXOF = false,
    rounds = 24
  ) {
    super();
    this.blockLen = blockLen;
    this.suffix = suffix;
    this.outputLen = outputLen;
    this.enableXOF = enableXOF;
    this.rounds = rounds;
    anumber(outputLen);
    if (!(0 < blockLen && blockLen < 200))
      throw new Error('only keccak-f1600 function is supported');
    this.state = new Uint8Array(200);
    this.state32 = u32(this.state);
  }

  clone(): Keccak {
    return this._cloneInto();
  }

  protected keccak(): void {
    swap32IfBE(this.state32);
    keccakP(this.state32, this.rounds);
    swap32IfBE(this.state32);
    this.posOut = 0;
    this.pos = 0;
  }

  update(data: Input): this {
    aexists(this);
    const bytes = toBytes(data);
    abytes(bytes);
    const { blockLen, state } = this;
    const len = bytes.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      for (let i = 0; i < take; i++) state[this.pos++] ^= bytes[pos++];
      if (this.pos === blockLen) this.keccak();
    }
    return this;
  }

  protected finish(): void {
    if (this.finished) return;
    this.finished = true;
    const { state, suffix, pos, blockLen } = this;
    state[pos] ^= suffix;
    if ((suffix & 0x80) !== 0 && pos === blockLen - 1) this.keccak();
    state[blockLen - 1] ^= 0x80;
    this.keccak();
  }

  protected writeInto(out: Uint8Array): Uint8Array {
    aexists(this, false);
    abytes(out);
    this.finish();
    const bufferOut = this.state;
    const { blockLen } = this;
    for (let pos = 0, len = out.length; pos < len; ) {
      if (this.posOut >= blockLen) this.keccak();
      const take = Math.min(blockLen - this.posOut, len - pos);
      out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
      this.posOut += take;
      pos += take;
    }
    return out;
  }

  xofInto(out: Uint8Array): Uint8Array {
    if (!this.enableXOF) throw new Error('XOF is not possible for this instance');
    return this.writeInto(out);
  }

  xof(bytes: number): Uint8Array {
    anumber(bytes);
    return this.xofInto(new Uint8Array(bytes));
  }

  digestInto(out: Uint8Array): Uint8Array {
    aoutput(out, this);
    if (this.finished) throw new Error('digest() was already called');
    this.writeInto(out);
    this.destroy();
    return out;
  }

  digest(): Uint8Array {
    return this.digestInto(new Uint8Array(this.outputLen));
  }

  destroy(): void {
    this.destroyed = true;
    clean(this.state);
  }

  _cloneInto(to?: Keccak): Keccak {
    const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
    to ??= new Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
    to.state32.set(this.state32);
    to.pos = this.pos;
    to.posOut = this.posOut;
    to.finished = this.finished;
    to.rounds = rounds;
    to.suffix = suffix;
    to.outputLen = outputLen;
    to.enableXOF = enableXOF;
    to.destroyed = this.destroyed;
    return to;
  }
}

/** keccak-256 hash function (Ethereum-compatible, different from SHA3-256). */
export const keccak_256: CHash = /* @__PURE__ */ (() =>
  createHasher(() => new Keccak(136, 0x01, 32)))();
