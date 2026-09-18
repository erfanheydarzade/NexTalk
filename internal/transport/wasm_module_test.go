package transport

// Hand-assembled WASM queue module implementing the transport ABI, so the
// WASM runtime test needs no external toolchain (no tinygo/wat2wasm).
//
// Layout: memory 20 pages; globals running/attached/qread/qwrite/heap;
// FIFO record queue [BE32 len][bytes] at [wQStart,wQEnd); static out region
// at wOut; "message" data segment at wOut; bump heap at wHeap0.

import (
	"context"
	"time"
)

const (
	wQStart = 0x1000
	wQEnd   = 0x11000
	wOut    = 0x20000
	wMbox   = 0x100
	wSec    = 0x110
	wHeap0  = 0x30000
)

// --- tiny assembler ---

type asm struct {
	code []byte
}

func (a *asm) b(v ...byte) { a.code = append(a.code, v...) }
func (a *asm) u(v uint32)  { a.code = append(a.code, uleb(v)...) }

// i32c emits i32.const with SIGNED LEB128 (s33): values 64..127,
// 8192..16383, ... need an extra byte versus unsigned LEB — emitting
// unsigned here silently turns 64 into -64.
func (a *asm) i32c(v int32)  { a.b(0x41); a.code = append(a.code, sleb(v)...) }
func (a *asm) i64c(v int64)  { a.b(0x42); a.code = append(a.code, sleb64(v)...) }
func (a *asm) get(i uint32)  { a.b(0x20); a.u(i) }
func (a *asm) set(i uint32)  { a.b(0x21); a.u(i) }
func (a *asm) gget(i uint32) { a.b(0x23); a.u(i) }
func (a *asm) gset(i uint32) { a.b(0x24); a.u(i) }
func (a *asm) load8()        { a.b(0x2c, 0x00, 0x00) }
func (a *asm) store8()       { a.b(0x3a, 0x00, 0x00) }
func (a *asm) add()          { a.b(0x6a) }
func (a *asm) sub()          { a.b(0x6b) }
func (a *asm) shl()          { a.b(0x74) }
func (a *asm) shrU()         { a.b(0x76) }
func (a *asm) or()           { a.b(0x72) }
func (a *asm) xor()          { a.b(0x73) }
func (a *asm) eqz()          { a.b(0x45) }
func (a *asm) eq()           { a.b(0x46) }
func (a *asm) ne()           { a.b(0x47) }
func (a *asm) ltU()          { a.b(0x49) }
func (a *asm) gtU()          { a.b(0x4b) }
func (a *asm) geU()          { a.b(0x4f) }
func (a *asm) i64extend()    { a.b(0xad) }
func (a *asm) i64shl()       { a.b(0x86) }
func (a *asm) i64or()        { a.b(0x84) }
func (a *asm) block()        { a.b(0x02, 0x40) }
func (a *asm) loop()         { a.b(0x03, 0x40) }
func (a *asm) br(d uint32)   { a.b(0x0c); a.u(d) }
func (a *asm) brIf(d uint32) { a.b(0x0d); a.u(d) }
func (a *asm) ifI32()        { a.b(0x04, 0x7f) }
func (a *asm) ifVoid()       { a.b(0x04, 0x40) }
func (a *asm) els()          { a.b(0x05) }
func (a *asm) end()          { a.b(0x0b) }
func (a *asm) ret()          { a.b(0x0f) }
func (a *asm) drop()         { a.b(0x1a) }

// packOut emits: push ((u64)ptr<<32)|len.
func (a *asm) packOut(ptr uint32, length uint32) {
	a.i32c(int32(ptr))
	a.i64extend()
	a.i64c(32)
	a.i64shl()
	a.i64c(int64(length))
	a.i64or()
}

func uleb(v uint32) []byte {
	var out []byte
	for {
		c := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			return append(out, c)
		}
		out = append(out, c|0x80)
	}
}

// sleb encodes int32 as signed LEB128.
func sleb(v int32) []byte {
	var out []byte
	for {
		c := byte(v & 0x7f)
		v >>= 7 // arithmetic shift
		sign := c&0x40 != 0
		if (v == 0 && !sign) || (v == -1 && sign) {
			return append(out, c)
		}
		out = append(out, c|0x80)
	}
}

// sleb64 encodes int64 as signed LEB128.
func sleb64(v int64) []byte {
	var out []byte
	for {
		c := byte(v & 0x7f)
		v >>= 7 // arithmetic shift
		sign := c&0x40 != 0
		if (v == 0 && !sign) || (v == -1 && sign) {
			return append(out, c)
		}
		out = append(out, c|0x80)
	}
}

// memcpy(dst, src, n) with local i as counter. Uses locals (dst,src,n,i).
func (a *asm) memcpy(dst, src, n, i uint32) {
	a.block()
	a.loop()
	a.get(i)
	a.get(n)
	a.geU()
	a.brIf(1)
	a.get(dst)
	a.get(i)
	a.add()
	a.get(src)
	a.get(i)
	a.add()
	a.load8()
	a.store8()
	a.get(i)
	a.i32c(1)
	a.add()
	a.set(i)
	a.br(0)
	a.end()
	a.end()
}

// memeq16 pushes 1 if [local pa, +16) == [pbAddr, +16). Uses locals i
// (counter) and acc (mismatch accumulator).
func (a *asm) memeq16(paLocal uint32, pbAddr uint32, i, acc uint32) {
	a.i32c(0)
	a.set(acc)
	a.i32c(0)
	a.set(i)
	a.block()
	a.loop()
	a.get(i)
	a.i32c(16)
	a.geU()
	a.brIf(1)
	a.get(paLocal)
	a.get(i)
	a.add()
	a.load8()
	a.i32c(int32(pbAddr))
	a.get(i)
	a.add()
	a.load8()
	a.xor()
	a.get(acc)
	a.or()
	a.set(acc)
	a.get(i)
	a.i32c(1)
	a.add()
	a.set(i)
	a.br(0)
	a.end()
	a.end()
	a.get(acc)
	a.eqz()
}

var _ = context.Background
var _ = time.Second
