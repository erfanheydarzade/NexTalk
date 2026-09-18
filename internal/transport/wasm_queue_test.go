package transport

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// Queue-module function bodies + section assembly + ABI test.
// (Assembler primitives live in wasm_module_test.go.)

// storeBE32 stores u32 at addr big-endian via 4 store8.
func (a *asm) storeBE32(addrLocal, valLocal uint32) {
	a.get(addrLocal)
	a.get(valLocal)
	a.i32c(24)
	a.shrU()
	a.store8()
	a.get(addrLocal)
	a.i32c(1)
	a.add()
	a.get(valLocal)
	a.i32c(16)
	a.shrU()
	a.store8()
	a.get(addrLocal)
	a.i32c(2)
	a.add()
	a.get(valLocal)
	a.i32c(8)
	a.shrU()
	a.store8()
	a.get(addrLocal)
	a.i32c(3)
	a.add()
	a.get(valLocal)
	a.store8()
}

// bodyInit: () -> 0 (params ignored).
func bodyInit() []byte {
	a := &asm{}
	a.i32c(0)
	a.end()
	return a.code
}

// bodyCaps: pack(wOut, 7); "message" lives in the data segment.
func bodyCaps() []byte {
	a := &asm{}
	a.packOut(wOut, 7)
	a.end()
	return a.code
}

// bodyStartStop: set running, return 0. val is 1 or 0.
func bodyStartStop(val int32) []byte {
	a := &asm{}
	a.i32c(val)
	a.gset(0)
	a.i32c(0)
	a.end()
	return a.code
}

// bodyStatus: return running.
func bodyStatus() []byte {
	a := &asm{}
	a.gget(0)
	a.end()
	return a.code
}

// bodyAlloc: bump heap. params: n. No extra locals.
func bodyAlloc() []byte {
	a := &asm{}
	a.gget(4)
	a.gget(4)
	a.get(0)
	a.add()
	a.gset(4)
	a.end()
	return a.code
}

// bodyDetach: attached=0; return 0. params: mptr.
func bodyDetach() []byte {
	a := &asm{}
	a.i32c(0)
	a.gset(1)
	a.i32c(0)
	a.end()
	return a.code
}

// bodySend: params fptr0 flen1 rptr2 rlen3; locals dst4 i5.
// Returns 0 ok, 1 not started, 2 bad args, 3 full.
func bodySend() []byte {
	a := &asm{}
	// !running -> 1
	a.gget(0)
	a.eqz()
	a.ifVoid()
	a.i32c(1)
	a.ret()
	a.end()
	// flen==0 -> 2
	a.get(1)
	a.eqz()
	a.ifVoid()
	a.i32c(2)
	a.ret()
	a.end()
	// flen>40960 -> 2
	a.get(1)
	a.i32c(40960)
	a.gtU()
	a.ifVoid()
	a.i32c(2)
	a.ret()
	a.end()
	// rlen>64 -> 2
	a.get(3)
	a.i32c(64)
	a.gtU()
	a.ifVoid()
	a.i32c(2)
	a.ret()
	a.end()
	// qwrite+4+flen > QEND -> 3
	a.gget(3)
	a.get(1)
	a.add()
	a.i32c(4)
	a.add()
	a.i32c(int32(wQEnd))
	a.gtU()
	a.ifVoid()
	a.i32c(3)
	a.ret()
	a.end()
	// dst = qwrite
	a.gget(3)
	a.set(4)
	// store BE len
	a.storeBE32(4, 1)
	// dst += 4
	a.get(4)
	a.i32c(4)
	a.add()
	a.set(4)
	// memcpy(dst, fptr, flen)
	a.i32c(0)
	a.set(5)
	a.block()
	a.loop()
	a.get(5)
	a.get(1)
	a.geU()
	a.brIf(1)
	a.get(4)
	a.get(5)
	a.add()
	a.get(0)
	a.get(5)
	a.add()
	a.load8()
	a.store8()
	a.get(5)
	a.i32c(1)
	a.add()
	a.set(5)
	a.br(0)
	a.end()
	a.end()
	// qwrite += 4+flen
	a.gget(3)
	a.get(1)
	a.i32c(4)
	a.add()
	a.add()
	a.gset(3)
	a.i32c(0)
	a.end()
	return a.code
}

// bodyAttach: params mptr0 sptr1 shard2..router5. locals dst6 src7 n8 i9.
// Copies 16B mailbox + 32B secret to fixed addrs; sets attached.
func bodyAttach() []byte {
	a := &asm{}
	// copy(dst=wMbox, src=mptr, n=16)
	a.i32c(int32(wMbox))
	a.set(6)
	a.get(0)
	a.set(7)
	a.i32c(16)
	a.set(8)
	a.i32c(0)
	a.set(9)
	a.block()
	a.loop()
	a.get(9)
	a.get(8)
	a.geU()
	a.brIf(1)
	a.get(6)
	a.get(9)
	a.add()
	a.get(7)
	a.get(9)
	a.add()
	a.load8()
	a.store8()
	a.get(9)
	a.i32c(1)
	a.add()
	a.set(9)
	a.br(0)
	a.end()
	a.end()
	// copy(dst=wSec, src=sptr, n=32)
	a.i32c(int32(wSec))
	a.set(6)
	a.get(1)
	a.set(7)
	a.i32c(32)
	a.set(8)
	a.i32c(0)
	a.set(9)
	a.block()
	a.loop()
	a.get(9)
	a.get(8)
	a.geU()
	a.brIf(1)
	a.get(6)
	a.get(9)
	a.add()
	a.get(7)
	a.get(9)
	a.add()
	a.load8()
	a.store8()
	a.get(9)
	a.i32c(1)
	a.add()
	a.set(9)
	a.br(0)
	a.end()
	a.end()
	a.i32c(1)
	a.gset(1)
	a.i32c(0)
	a.end()
	return a.code
}

// bodyPoll: params limit0 mptr1 has2. locals p3 n4 ln5 i6 acc7.
// Returns pack(out, span) of drained records.
func bodyPoll() []byte {
	a := &asm{}
	// if has != 0: require attached + mailbox match, else empty result.
	a.get(2)
	a.ifVoid()
	a.gget(1)
	a.eqz()
	a.ifVoid()
	a.packOut(wOut, 0)
	a.ret()
	a.end()
	a.memeq16(1, uint32(wMbox), 6, 7)
	a.eqz()
	a.ifVoid()
	a.packOut(wOut, 0)
	a.ret()
	a.end()
	a.end()
	// p = qread; n = 0
	a.gget(2)
	a.set(3)
	a.i32c(0)
	a.set(4)
	a.block()
	a.loop()
	// n >= limit -> done
	a.get(4)
	a.get(0)
	a.geU()
	a.brIf(1)
	// (qwrite - p) < 4 -> done
	a.gget(3)
	a.get(3)
	a.sub()
	a.i32c(4)
	a.ltU()
	a.brIf(1)
	// ln = BE32(p)
	a.get(3)
	a.load8()
	a.i32c(24)
	a.shl()
	a.get(3)
	a.i32c(1)
	a.add()
	a.load8()
	a.i32c(16)
	a.shl()
	a.or()
	a.get(3)
	a.i32c(2)
	a.add()
	a.load8()
	a.i32c(8)
	a.shl()
	a.or()
	a.get(3)
	a.i32c(3)
	a.add()
	a.load8()
	a.or()
	a.set(5)
	// ln==0 || ln>40960 -> done
	a.get(5)
	a.eqz()
	a.brIf(1)
	a.get(5)
	a.i32c(40960)
	a.gtU()
	a.brIf(1)
	// end = p+4+ln -> reuse ln; qwrite < end -> done
	a.get(3)
	a.get(5)
	a.add()
	a.i32c(4)
	a.add()
	a.set(5)
	a.gget(3)
	a.get(5)
	a.ltU()
	a.brIf(1)
	// p = end; n++
	a.get(5)
	a.set(3)
	a.get(4)
	a.i32c(1)
	a.add()
	a.set(4)
	a.br(0)
	a.end()
	a.end()
	// span = p - qread -> reuse ln
	a.get(3)
	a.gget(2)
	a.sub()
	a.set(5)
	// memcpy(OUT, qread, span)
	a.i32c(0)
	a.set(6)
	a.block()
	a.loop()
	a.get(6)
	a.get(5)
	a.geU()
	a.brIf(1)
	a.i32c(int32(wOut))
	a.get(6)
	a.add()
	a.gget(2)
	a.get(6)
	a.add()
	a.load8()
	a.store8()
	a.get(6)
	a.i32c(1)
	a.add()
	a.set(6)
	a.br(0)
	a.end()
	a.end()
	// qread = p; if empty reset cursors
	a.get(3)
	a.gset(2)
	a.gget(2)
	a.gget(3)
	a.sub()
	a.eqz()
	a.ifVoid()
	a.i32c(int32(wQStart))
	a.gset(2)
	a.i32c(int32(wQStart))
	a.gset(3)
	a.end()
	// return pack(OUT, span)
	a.i32c(int32(wOut))
	a.i64extend()
	a.i64c(32)
	a.i64shl()
	a.get(5)
	a.i64extend()
	a.i64or()
	a.end()
	return a.code
}

// --- module assembly ---

func sec(id byte, content []byte) []byte {
	out := []byte{id}
	out = append(out, uleb(uint32(len(content)))...)
	return append(out, content...)
}


// sendBodyOverride swaps the send body for fault isolation experiments.
var sendBodyOverride []byte

// buildQueueModule assembles the test transport module.
func buildQueueModule() []byte {
	sendBody := bodySend()
	if sendBodyOverride != nil {
		sendBody = sendBodyOverride
	}
	i32 := byte(0x7f)
	mkType := func(params int, res byte) []byte {
		t := []byte{0x60, byte(params)}
		for i := 0; i < params; i++ {
			t = append(t, i32)
		}
		if res == 0 {
			return append(t, 0x00)
		}
		return append(t, 0x01, res)
	}
	types := []byte{}
	types = append(types, uleb(7)...)
	types = append(types, mkType(2, i32)...)  // 0 init
	types = append(types, mkType(0, 0x7e)...) // 1 caps
	types = append(types, mkType(0, i32)...)  // 2 start/stop/status
	types = append(types, mkType(4, i32)...)  // 3 send
	types = append(types, mkType(6, i32)...)  // 4 attach
	types = append(types, mkType(1, i32)...)  // 5 detach, alloc
	types = append(types, mkType(3, 0x7e)...) // 6 poll

	funcs := []byte{}
	funcs = append(funcs, uleb(10)...)
	for _, ti := range []byte{0, 1, 2, 2, 3, 4, 5, 6, 2, 5} {
		funcs = append(funcs, ti)
	}

	mem := []byte{uleb(1)[0], 0x00, 20}

	glob := []byte{}
	glob = append(glob, uleb(5)...)
	for _, v := range []uint32{0, 0, wQStart, wQStart, wHeap0} {
		glob = append(glob, i32, 0x01, 0x41)
		glob = append(glob, uleb(v)...)
		glob = append(glob, 0x0b)
	}

	type exp struct {
		name string
		kind byte
		idx  uint32
	}
	exps := []exp{
		{"memory", 0x02, 0},
		{"ntx_init", 0x00, 0},
		{"ntx_caps", 0x00, 1},
		{"ntx_start", 0x00, 2},
		{"ntx_stop", 0x00, 3},
		{"ntx_send", 0x00, 4},
		{"ntx_attach", 0x00, 5},
		{"ntx_detach", 0x00, 6},
		{"ntx_poll", 0x00, 7},
		{"ntx_status", 0x00, 8},
		{"ntx_alloc", 0x00, 9},
	}
	xsec := []byte{}
	xsec = append(xsec, uleb(uint32(len(exps)))...)
	for _, e := range exps {
		xsec = append(xsec, strExport(e.name)...)
		xsec = append(xsec, e.kind)
		xsec = append(xsec, uleb(e.idx)...)
	}

	bodies := [][]byte{
		withLocals(0, bodyInit()), withLocals(0, bodyCaps()), withLocals(0, bodyStartStop(1)), withLocals(0, bodyStartStop(0)),
		withLocals(2, sendBody), withLocals(4, bodyAttach()),
		withLocals(0, bodyDetach()), withLocals(5, bodyPoll()), withLocals(0, bodyStatus()), withLocals(0, bodyAlloc()),
	}
	code := []byte{}
	code = append(code, uleb(uint32(len(bodies)))...)
	for _, b := range bodies {
		code = append(code, uleb(uint32(len(b)))...)
		code = append(code, b...)
	}

	data := []byte{}
	data = append(data, uleb(1)...)
	data = append(data, 0x00, 0x41)
	data = append(data, uleb(wOut)...)
	data = append(data, 0x0b, 0x07)
	data = append(data, []byte("message")...)

	mod := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	mod = append(mod, sec(1, types)...)
	mod = append(mod, sec(3, funcs)...)
	mod = append(mod, sec(5, mem)...)
	mod = append(mod, sec(6, glob)...)
	mod = append(mod, sec(7, xsec)...)
	mod = append(mod, sec(10, code)...)
	mod = append(mod, sec(11, data)...)
	return mod
}

func strExport(s string) []byte {
	return append(uleb(uint32(len(s))), s...)
}

// withLocals prepends a locals vector of n i32 to a body.
func withLocals(n int, body []byte) []byte {
	if n == 0 {
		return append([]byte{0x00}, body...)
	}
	out := []byte{0x01, byte(n), 0x7f}
	return append(out, body...)
}

func TestWASMQueueTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	mod := buildQueueModule()
	mf, err := ParseManifest([]byte(`{"id":"wasm-queue","name":"Wasm Queue","version":"0.0.1","api_version":"1","entry":"queue.wasm","capabilities":["message"],"permissions":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	tr, err := NewWASMTransport(ctx, mod, mf, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close(ctx)
	if !SupportsCapability(tr, "message") {
		t.Fatal("must declare message")
	}
	if err := tr.Start(ctx); err != nil {
		t.Fatal(err)
	}
	mbox := bytes.Repeat([]byte{0xA}, 16)
	sec := bytes.Repeat([]byte{0xB}, 32)
	if err := tr.AttachMailbox(ctx, mbox, sec, "", ""); err != nil {
		t.Fatal(err)
	}
	pub := bytes.Repeat([]byte{0xC}, 32)
	f1 := append([]byte{0x03}, []byte("first")...)
	f2 := append([]byte{0x03}, []byte("second")...)
	if err := tr.SendFrame(ctx, f1, RouteHint{RecipientPub: pub}); err != nil {
		t.Fatal(err)
	}
	if err := tr.SendFrame(ctx, f2, RouteHint{RecipientPub: pub}); err != nil {
		t.Fatal(err)
	}
	got, err := tr.PollFrames(ctx, 10, mbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !bytes.Equal(got[0], f1) || !bytes.Equal(got[1], f2) {
		t.Fatalf("poll mismatch: %v", got)
	}
	// Drained.
	got, err = tr.PollFrames(ctx, 10, mbox)
	if err != nil || len(got) != 0 {
		t.Fatalf("must drain: %v %v", got, err)
	}
	// Wrong mailbox sees nothing.
	got, err = tr.PollFrames(ctx, 10, bytes.Repeat([]byte{0xD}, 16))
	if err != nil || len(got) != 0 {
		t.Fatalf("wrong mailbox must be empty: %v", got)
	}
	running, _, err := tr.Status(ctx)
	if err != nil || !running {
		t.Fatal("must be running")
	}
	if err := tr.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	// Send after stop fails.
	if err := tr.SendFrame(ctx, f1, RouteHint{RecipientPub: pub}); err == nil {
		t.Fatal("send after stop must fail")
	}
}

func TestWASMRefusesBadModule(t *testing.T) {	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mf, _ := ParseManifest([]byte(`{"id":"wasm-bad","name":"B","version":"1","api_version":"1","entry":"x.wasm","capabilities":["message"],"permissions":[]}`))
	if _, err := NewWASMTransport(ctx, []byte{0x00, 0x61, 0x73, 0x6d}, mf, nil); err == nil {
		t.Fatal("truncated module must fail")
	}
	if _, err := NewWASMTransport(ctx, buildQueueModule(), mf, nil); err != nil {
		// valid module instantiates (manifest id mismatch is fine: module
		// reports caps, core checks api + caps, not entry id here)
		t.Fatal(err)
	}
}
