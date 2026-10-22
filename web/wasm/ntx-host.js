/*
 * ntx-host.js — browser-side runtime for .wasm NexTalk transports.
 *
 * Implements WASM transport ABI v1 (see internal/transport/wasm.go) with the
 * browser's own WebAssembly engine, because the Go bridge cannot use wazero
 * under GOOS=js (not verified to build; see docs/wasm.md). Go talks to the
 * handle returned by instantiate() through internal/wasmbridge/jshost.go.
 *
 * ABI recap:  blobs are (ptr,len) pairs into the module's exported "memory";
 * data returns pack (ptr<<32|len) as i64; poll returns BE32-length-prefixed
 * full frames. Sandbox: the module gets linear memory plus an optional
 * `ntx.log` import and nothing else — no WASI, no sockets, no filesystem.
 * Any other import makes WebAssembly.instantiate fail (LinkError).
 *
 * Usage:   <script src="wasm/ntx-host.js"></script>   (after NexTalk loads)
 *          NexTalkTransportHost.register(NexTalk);    // calls _registerHost
 */
(function (root) {
  'use strict';

  var MAX_FRAME = 40 * 1024;                 // same ceiling as the process RPC
  var MAX_BLOB = MAX_FRAME * 33 + 16;        // 32 frames + prefixes + slack
  var SCRATCH = 1 << 20;                     // fallback region when no ntx_alloc
  var SCRATCH_SPAN = 1 << 20;

  function need(ex, name) {
    if (typeof ex[name] !== 'function') throw new Error('transport module missing export ' + JSON.stringify(name));
    return ex[name];
  }

  async function instantiate(id, wasmBytes, cfgBytes) {
    var memory = null;
    var logs = [];
    var imports = {
      ntx: {
        log: function (ptr, len) {
          try {
            if (!memory || len >= 4096) return;
            logs.push(new TextDecoder().decode(new Uint8Array(memory.buffer, ptr >>> 0, len >>> 0)));
            if (logs.length > 200) logs.shift();
          } catch (e) { /* diagnostics only */ }
        }
      }
    };
    var res = await WebAssembly.instantiate(wasmBytes, imports);
    var ex = res.instance.exports;
    memory = ex.memory;
    if (!(memory instanceof WebAssembly.Memory)) throw new Error('transport module does not export "memory"');
    ['ntx_init', 'ntx_caps', 'ntx_start', 'ntx_stop', 'ntx_send', 'ntx_attach', 'ntx_detach', 'ntx_poll', 'ntx_status']
      .forEach(function (n) { need(ex, n); });

    var destroyed = false;
    var scratchOff = 0; // bump offset inside the fallback scratch, reset per ABI call

    function live() { if (destroyed) throw new Error('transport instance destroyed'); }
    function resetScratch() { scratchOff = 0; }

    // Copy `data` into module memory and return its pointer. Prefers the
    // module's ntx_alloc; otherwise a fixed 1 MiB scratch region. (The wazero
    // host reuses the SAME scratch address for every blob of one call, which
    // would overwrite send()'s frame with its recipient for alloc-less
    // modules; this host bump-allocates within the call instead.)
    function writeMem(data) {
      if (typeof ex.ntx_alloc === 'function') {
        var p = ex.ntx_alloc(data.length) >>> 0;
        var mem = new Uint8Array(memory.buffer); // fetch AFTER alloc: it may grow memory
        if (p + data.length > mem.length) throw new Error('ntx_alloc returned an out-of-bounds region');
        mem.set(data, p);
        return p;
      }
      if (data.length > SCRATCH_SPAN) throw new Error('argument too large');
      var at = SCRATCH + scratchOff;
      if (scratchOff + data.length > SCRATCH_SPAN) throw new Error('scratch region exhausted');
      if (at + data.length > memory.buffer.byteLength) {
        var need64k = Math.ceil((at + data.length - memory.buffer.byteLength) / 65536);
        memory.grow(need64k);
      }
      new Uint8Array(memory.buffer).set(data, at);
      scratchOff += (data.length + 7) & ~7;
      return at;
    }

    function readBlob(packed) {
      var u = BigInt.asUintN(64, packed);
      var ptr = Number(u >> 32n);
      var len = Number(u & 0xffffffffn);
      if (len > MAX_BLOB) throw new Error('blob too large (' + len + ')');
      var mem = new Uint8Array(memory.buffer);
      if (ptr + len > mem.length) throw new Error('blob out of bounds');
      return mem.slice(ptr, ptr + len); // copy out immediately (module may reuse the region)
    }

    // ntx_init + ntx_caps happen at instantiate time, as in NewWASMTransport.
    resetScratch();
    var cfg = cfgBytes && cfgBytes.length ? cfgBytes : new Uint8Array(0);
    var cfgPtr = writeMem(cfg);
    var rc = ex.ntx_init(cfgPtr, cfg.length);
    if (rc !== 0) throw new Error('ntx_init refused: ' + rc);
    var caps = new TextDecoder().decode(readBlob(ex.ntx_caps()));

    return {
      caps: caps,
      start: function () { live(); return ex.ntx_start(); },
      stop: function () { live(); return ex.ntx_stop(); },
      send: function (frame, recipient) {
        live();
        if (frame.length === 0 || frame.length > MAX_FRAME) return 2;
        resetScratch();
        var fp = writeMem(frame);
        var rp = writeMem(recipient);
        return ex.ntx_send(fp, frame.length, rp, recipient.length);
      },
      // v1 queue transports ignore shard/router URLs (passed as 0,0,0,0).
      attach: function (mailbox, secret) {
        live();
        if (mailbox.length !== 16 || secret.length !== 32) return 2;
        resetScratch();
        var mp = writeMem(mailbox);
        var sp = writeMem(secret);
        return ex.ntx_attach(mp, sp, 0, 0, 0, 0);
      },
      detach: function (mailbox) {
        live();
        if (mailbox.length !== 16) return 2;
        resetScratch();
        return ex.ntx_detach(writeMem(mailbox));
      },
      poll: function (limit, mailbox) {
        live();
        limit = limit > 0 && limit <= 32 ? limit : 32;
        resetScratch();
        var has = mailbox && mailbox.length === 16;
        var mp = has ? writeMem(mailbox) : 0;
        return readBlob(ex.ntx_poll(limit, mp, has ? 1 : 0));
      },
      status: function () { live(); return ex.ntx_status(); },
      logs: function () { return logs.slice(); },
      destroy: function () { destroyed = true; }
    };
  }

  var host = {
    abi: 1,
    instantiate: instantiate,
    // Hook the host into a loaded NexTalk bridge (api >= 3).
    register: function (NexTalk) {
      if (!NexTalk || !NexTalk.transport || typeof NexTalk.transport._registerHost !== 'function') {
        throw new Error('NexTalk.transport is missing: this build predates API revision 3');
      }
      var r = NexTalk.transport._registerHost(host);
      if (r && r.error) throw new Error(r.error);
      return r;
    }
  };

  root.NexTalkTransportHost = host;
  if (typeof module !== 'undefined' && module.exports) module.exports = host;
})(typeof globalThis !== 'undefined' ? globalThis : this);
