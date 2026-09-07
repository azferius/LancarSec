// Offline smoke test of the stage-2 proof-of-work bundle: no browser, no
// proxy, no network.  `node hack/powsmoke.mjs`, exit 0 means the solver works.
//
// Why this exists: the wave-10 rebrand renamed the served asset route but
// missed the copy of the path inside pow.min.js's worker script, so
// importScripts 404'd, every worker resolved with no solution, and stage 2 was
// unsolvable for six days without a single test failing.  The Go test
// TestPowAssetsReferenceOnlyServedPaths catches that exact mismatch cheaply;
// this harness is the deeper check - it actually RUNS the bundle and proves it
// produces the solution the server will accept.  Run it whenever pow.min.js or
// crypto-js.min.js is refreshed.
//
// It emulates just enough DOM/Worker surface to run BalooPow end to end, and
// resolves importScripts against SERVED exactly like a browser resolves it
// against the proxy's routes: an unserved path throws, which is what the real
// bug did.
import fs from 'node:fs';
import vm from 'node:vm';
import crypto from 'node:crypto';

const root = new URL('../global/pow/', import.meta.url);
const powSrc = fs.readFileSync(new URL('pow.min.js', root), 'utf8');
const cjsSrc = fs.readFileSync(new URL('crypto-js.min.js', root), 'utf8');

const SERVED = { '/_lancarsec/crypto-js.min.js': cjsSrc };
const importedPaths = [];

class FakeWorker {
  constructor(src) {
    const self_ = {
      onmessage: null,
      postMessage: (d) => queueMicrotask(() => this.onmessage && this.onmessage({ data: d })),
      close: () => {},
      location: { origin: 'https://example.test' },
      importScripts: (...urls) => {
        for (const u of urls) {
          const path = u.replace('https://example.test', '');
          importedPaths.push(path);
          if (!SERVED[path]) throw new Error('importScripts: 404 ' + path);
          vm.runInContext(SERVED[path], ctx);
        }
      },
    };
    const ctx = vm.createContext({ self: self_, navigator: { hardwareConcurrency: 2 }, console });
    ctx.globalThis = ctx;
    ctx.importScripts = self_.importScripts;
    ctx.postMessage = self_.postMessage;
    vm.runInContext(src, ctx);
    this._ctx = ctx; this._self = self_;
  }
  postMessage(d) { this._self.onmessage({ data: d }); }
  terminate() {}
}

const blobs = new Map();
let n = 0;
const sandbox = {
  console,
  navigator: { hardwareConcurrency: 2 },
  Blob: class { constructor(parts) { this.text = parts.join(''); } },
  URL: { createObjectURL: (b) => { const k = 'blob:' + (n++); blobs.set(k, b.text); return k; } },
  Worker: class { constructor(url) { return new FakeWorker(blobs.get(url)); } },
  HTMLElement: class {},
  Promise, Date, Math, Object, Array, String, Number, JSON, Error,
};
sandbox.globalThis = sandbox;
const ctx = vm.createContext(sandbox);
vm.runInContext(powSrc, ctx);

// Mint a challenge the way core/server does: publicSalt + a hex answer of
// `difficulty` chars, challenge = SHA256(salt + answer).
const difficulty = 3;
const publicSalt = 'abcdef0123456789';
const answer = 'a7f';
const challenge = crypto.createHash('sha256').update(publicSalt + answer).digest('hex');

const solver = vm.runInContext(
  `new BalooPow(${JSON.stringify(publicSalt)}, ${difficulty}, ${JSON.stringify(challenge)}, false)`, ctx);

const result = await solver.Solve();

console.log('imported paths:', [...new Set(importedPaths)]);
if (!result) { console.log('RESULT: null — solver found nothing'); process.exit(1); }
console.log('solution:', result.solution, 'expected:', answer);
const wantAccess = crypto.createHash('sha256').update(answer + publicSalt).digest('hex');
console.log('access matches server derivation:', result.access === wantAccess);
process.exit(result.solution === answer && result.access === wantAccess ? 0 : 1);
