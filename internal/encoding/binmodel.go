// This file extends the original binmodel package with a compact, embedded-
// friendly wire format (v2), while keeping the original text-based format
// (Encode/Decode/Marshal/Unmarshal) untouched for backward compatibility.
//
// What changed and why (per discussion):
//
//  1. Field NAMES are kept in your Go code (schema), but the WIRE format
//     sends a 1-byte numeric ID instead of the name string. You still write
//     Add("mailbox", ...) — the schema maps "mailbox" -> 1 behind the scenes.
//
//  2. The header is binary, not text: no ':' or ',' parsing, no strconv.
//     Each header entry is: [1 byte fieldID][varint length]. No "::"
//     separator needed either — the body starts right after N header
//     entries, and length is derived from a leading field count byte.
//
//  3. Integers are encoded as raw binary (big-endian), not ASCII digits.
//     A uint64 timestamp costs 8 bytes instead of up to 10+ ASCII bytes,
//     and decoding is a single binary.BigEndian.Uint64 call — zero parsing.
//
//  4. A reflection-free hot path is provided via the BinMarshaler /
//     BinUnmarshaler interfaces. Structs that implement them skip
//     reflection entirely (safe for TinyGo / ESP32 / STM32). The old
//     reflection-based Marshal/Unmarshal is still there as a convenience
//     fallback for desktop/dev use.
//
//  5. Encoder2 keeps the same Reset() pattern as the original Encoder, so a
//     single encoder can be reused across many packets with ~zero
//     allocation in steady state. AddUint64Into/AddUint32Into take that
//     further with a caller-owned scratch buffer, for a genuinely
//     zero-allocation numeric-field hot path (see the doc comment on
//     AddUint64 for why AddUint64 itself still allocates).
//
//  6. Schema is immutable from outside the package (no exported setters),
//     so nothing can desync a wire protocol that's already deployed.
//
//  7. WrapPacket/UnwrapPacket add an optional framing envelope — magic
//     byte + major.minor version + schema ID + flags + length + CRC16 —
//     for noisy transports (UART, BLE, WiFi) where resync-after-corruption
//     and reading multiple packets off one buffer matter. HTTP/TCP callers
//     can skip it and use Encoder2/Decode2 directly. SchemaID lets a
//     receiver holding several packet types dispatch with a plain switch.
//
//  8. cmd/bingen generates MarshalBinID/UnmarshalBinID from `bin:"N"`
//     struct tags — no reflection AND no field-name strings anywhere in
//     the hot path, only Go consts. See AddID/FieldID/DecodeIDs.
package encoding

import (
	"encoding/binary"
	"errors"
)

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

var (
	ErrUnknownField    = errors.New("binmodel: unknown field name in schema")
	ErrTooManyFields   = errors.New("binmodel: schema supports at most 255 fields")
	ErrShortHeader     = errors.New("binmodel: truncated header")
	ErrShortBody       = errors.New("binmodel: truncated body")
	ErrBadVarint       = errors.New("binmodel: malformed varint length")
	ErrFieldIDNotFound = errors.New("binmodel: field id not present in schema")
)

// ---------------------------------------------------------------------
// Schema: name <-> 1-byte ID mapping, built once, reused for every packet.
// ---------------------------------------------------------------------

// Schema maps field names to small numeric IDs so the wire format never
// has to send the name itself. Build one Schema per packet type, once,
// e.g. at package init time, and share it across every Encode/Decode call.
//
// Schema is effectively immutable once built: nameToID/idToName are
// unexported and there are no setters, so nothing outside this package can
// mutate a live Schema and desync a wire protocol that's already deployed.
// If you need to change field IDs, build a new Schema (new ProtocolVersion
// too, if firmware in the field depends on the old one).
//
// ID identifies the *packet type* itself (SendPacket=1, AckPacket=2, ...),
// distinct from the per-field IDs inside it. It travels in the envelope
// (see WrapPacket) so a receiver holding several Schemas can dispatch on
// a single byte — switch schemaID { case SchemaSend: ... } — with no
// lookup and no reflection.
type Schema struct {
	ID       uint8
	nameToID map[string]uint8
	idToName []string // index 0 unused; IDs start at 1
}

// NewSchema builds a Schema from an ordered list of field names, tagged
// with a packet-type id (see Schema.ID). The name order determines the
// assigned field IDs (1-based), so keep it stable across versions of your
// program / firmware if you care about wire compatibility.
func NewSchema(id uint8, names ...string) (*Schema, error) {
	if len(names) > 255 {
		return nil, ErrTooManyFields
	}
	s := &Schema{
		ID:       id,
		nameToID: make(map[string]uint8, len(names)),
		idToName: make([]string, len(names)+1),
	}
	for i, n := range names {
		fid := uint8(i + 1)
		s.nameToID[n] = fid
		s.idToName[fid] = n
	}
	return s, nil
}

// MustSchema is NewSchema for package-init-time use, where a construction
// error means a programming mistake (too many fields) that should fail
// fast rather than be handled at runtime. Generated code (see cmd/bingen)
// uses this for its package-level Schema vars.
func MustSchema(id uint8, names ...string) *Schema {
	s, err := NewSchema(id, names...)
	if err != nil {
		panic(err)
	}
	return s
}

func (s *Schema) idFor(name string) (uint8, bool) {
	id, ok := s.nameToID[name]
	return id, ok
}

func (s *Schema) nameFor(id uint8) (string, bool) {
	if int(id) >= len(s.idToName) || id == 0 {
		return "", false
	}
	n := s.idToName[id]
	return n, n != ""
}

// ---------------------------------------------------------------------
// Encoder2: binary header + binary body, schema-driven.
// ---------------------------------------------------------------------

// Encoder2 builds a compact binary payload:
//
//	[fieldCount byte]
//	( [fieldID byte][varint length] ) * fieldCount
//	<raw field data, concatenated, in Add order>
//
// Reuse one Encoder2 across many packets via Reset() to avoid allocating.
type Encoder2 struct {
	schema *Schema
	ids    []uint8
	data   [][]byte
	bodyLn int
}

// NewEncoder2 creates an encoder bound to a schema.
func NewEncoder2(schema *Schema) *Encoder2 {
	return &Encoder2{schema: schema}
}

// Add appends a field by name (looked up in the schema) with raw bytes.
func (e *Encoder2) Add(name string, data []byte) (*Encoder2, error) {
	id, ok := e.schema.idFor(name)
	if !ok {
		return e, ErrUnknownField
	}
	return e.AddID(id, data), nil
}

// AddID appends a field by its raw numeric ID, with no schema lookup and
// no field-name string anywhere in the call. This is what generated
// MarshalBin code should call: field IDs become Go consts (see the
// generator), so the hot path never touches a string.
func (e *Encoder2) AddID(id uint8, data []byte) *Encoder2 {
	e.ids = append(e.ids, id)
	e.data = append(e.data, data)
	e.bodyLn += len(data)
	return e
}

// AddUint64 appends a field as 8 raw big-endian bytes instead of ASCII
// digits — this is the "send numbers as binary, not strconv" change.
//
// Note on allocation: buf is a local [8]byte array (stack-shaped), not
// make([]byte, 8). Go's escape analysis will still move it to the heap
// here, since e.data keeps a reference to buf[:] after return — so on its
// own this doesn't remove an allocation. For a true zero-alloc hot path
// (e.g. an ESP32 building 20k packets/sec), use AddUint64Into below.
func (e *Encoder2) AddUint64(name string, v uint64) (*Encoder2, error) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return e.Add(name, buf[:])
}

// AddUint32 is the 4-byte equivalent of AddUint64.
func (e *Encoder2) AddUint32(name string, v uint32) (*Encoder2, error) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return e.Add(name, buf[:])
}

// AddUint64Into writes v as 8 big-endian bytes into scratch (len >= 8) and
// adds scratch[:8] as the field data. Give it a caller-owned, reused
// buffer (e.g. one held alongside your Encoder2) and this path never
// allocates, on any Go compiler.
func (e *Encoder2) AddUint64Into(name string, v uint64, scratch []byte) (*Encoder2, error) {
	if len(scratch) < 8 {
		return e, ErrShortBody
	}
	binary.BigEndian.PutUint64(scratch[:8], v)
	return e.Add(name, scratch[:8])
}

// AddUint32Into is the 4-byte equivalent of AddUint64Into.
func (e *Encoder2) AddUint32Into(name string, v uint32, scratch []byte) (*Encoder2, error) {
	if len(scratch) < 4 {
		return e, ErrShortBody
	}
	binary.BigEndian.PutUint32(scratch[:4], v)
	return e.Add(name, scratch[:4])
}

// AddUint64ID and AddUint32ID are the AddID equivalents of AddUint64Into /
// AddUint32Into — numeric fields with no field-name string, for generated
// MarshalBin code.
func (e *Encoder2) AddUint64ID(id uint8, v uint64, scratch []byte) (*Encoder2, error) {
	if len(scratch) < 8 {
		return e, ErrShortBody
	}
	binary.BigEndian.PutUint64(scratch[:8], v)
	return e.AddID(id, scratch[:8]), nil
}

func (e *Encoder2) AddUint32ID(id uint8, v uint32, scratch []byte) (*Encoder2, error) {
	if len(scratch) < 4 {
		return e, ErrShortBody
	}
	binary.BigEndian.PutUint32(scratch[:4], v)
	return e.AddID(id, scratch[:4]), nil
}

// Bytes serializes the header + body into the final wire payload.
func (e *Encoder2) Bytes() ([]byte, error) {
	if len(e.ids) > 255 {
		return nil, ErrTooManyFields
	}

	// Worst case: 1 (count) + n*(1 id + 5 varint) + body.
	headerEstimate := 1 + len(e.ids)*6
	out := make([]byte, 0, headerEstimate+e.bodyLn)

	out = append(out, byte(len(e.ids)))
	for i, id := range e.ids {
		out = append(out, id)
		out = appendVarint(out, uint64(len(e.data[i])))
	}
	for _, d := range e.data {
		out = append(out, d...)
	}
	return out, nil
}

// Reset clears the encoder for reuse (same pattern as the original Encoder).
func (e *Encoder2) Reset() {
	e.ids = e.ids[:0]
	e.data = e.data[:0]
	e.bodyLn = 0
}

// ---------------------------------------------------------------------
// Decode2: parses the compact binary format back into named fields.
// ---------------------------------------------------------------------

// FieldID is a decoded field kept as its raw numeric ID — no schema
// lookup, no name string. Generated UnmarshalBin code switches on these
// IDs directly (they match the Go consts the generator emits).
type FieldID struct {
	ID   uint8
	Data []byte
}

// DecodeIDs parses a v2 payload into raw (ID, Data) pairs without needing
// a Schema at all. This is the fastest decode path and what generated
// UnmarshalBin code should use.
func DecodeIDs(payload []byte) ([]FieldID, error) {
	if len(payload) < 1 {
		return nil, ErrShortHeader
	}
	count := int(payload[0])
	pos := 1

	type hdrEntry struct {
		id  uint8
		len int
	}
	entries := make([]hdrEntry, 0, count)

	for i := 0; i < count; i++ {
		if pos >= len(payload) {
			return nil, ErrShortHeader
		}
		id := payload[pos]
		pos++
		length, n, err := readVarint(payload[pos:])
		if err != nil {
			return nil, err
		}
		pos += n
		entries = append(entries, hdrEntry{id: id, len: int(length)})
	}

	fields := make([]FieldID, 0, count)
	offset := pos
	for _, ent := range entries {
		if offset+ent.len > len(payload) {
			return nil, ErrShortBody
		}
		fields = append(fields, FieldID{ID: ent.id, Data: payload[offset : offset+ent.len]})
		offset += ent.len
	}
	if offset != len(payload) {
		return nil, ErrShortBody
	}

	return fields, nil
}

// Field2 is a decoded field, resolved back to its name via the schema.
type Field2 struct {
	Name string
	Data []byte
}

// Decode2 parses a v2 payload into an ordered slice of Field2, using the
// given schema to resolve IDs back to names. No text parsing, no strconv:
// every step is a byte read or a binary length decode.
func Decode2(schema *Schema, payload []byte) ([]Field2, error) {
	if len(payload) < 1 {
		return nil, ErrShortHeader
	}
	count := int(payload[0])
	pos := 1

	type hdrEntry struct {
		id  uint8
		len int
	}
	entries := make([]hdrEntry, 0, count)

	for i := 0; i < count; i++ {
		if pos >= len(payload) {
			return nil, ErrShortHeader
		}
		id := payload[pos]
		pos++
		length, n, err := readVarint(payload[pos:])
		if err != nil {
			return nil, err
		}
		pos += n
		entries = append(entries, hdrEntry{id: id, len: int(length)})
	}

	fields := make([]Field2, 0, count)
	offset := pos
	for _, ent := range entries {
		if offset+ent.len > len(payload) {
			return nil, ErrShortBody
		}
		name, ok := schema.nameFor(ent.id)
		if !ok {
			return nil, ErrFieldIDNotFound
		}
		fields = append(fields, Field2{Name: name, Data: payload[offset : offset+ent.len]})
		offset += ent.len
	}
	if offset != len(payload) {
		return nil, ErrShortBody
	}

	return fields, nil
}

// ---------------------------------------------------------------------
// Packet envelope: magic byte + version + flags + CRC16, wrapped around
// an Encoder2.Bytes() body. Optional — HTTP/TCP callers can skip it and
// use Encoder2/Decode2 directly. UART/BLE/WiFi callers get resync-ability
// and corruption detection.
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// Packet envelope: magic byte + major.minor version + schema ID + flags +
// length + CRC16, wrapped around an Encoder2.Bytes() body. Optional —
// HTTP/TCP callers can skip it and use Encoder2/Decode2 directly.
// UART/BLE/WiFi callers get resync-ability, corruption detection, and
// streaming (Length lets you read N packets back-to-back off one buffer).
// ---------------------------------------------------------------------

const (
	// PacketMagic marks the start of a framed packet, so a receiver that
	// loses byte alignment (common on UART/BLE) can scan forward for this
	// byte and resynchronize instead of having to read the whole header
	// to discover it's garbage.
	PacketMagic byte = 0xB2

	// ProtocolVersionMajor/Minor: Major bumps on a breaking wire-format
	// change (a receiver on a different Major should refuse to parse).
	// Minor bumps on an additive, backward-compatible change (new
	// optional field, new flag bit) — a receiver can accept any Minor
	// at its Major, per the usual "firmware only cares about Minor"
	// case.
	ProtocolVersionMajor byte = 1
	ProtocolVersionMinor byte = 0
)

// ErrBadMagic, ErrBadCRC, and ErrUnsupportedVersion signal framing/
// corruption/compatibility problems distinct from a malformed-but-aligned
// payload.
var (
	ErrBadMagic           = errors.New("binmodel: bad magic byte, out of sync")
	ErrBadCRC             = errors.New("binmodel: CRC mismatch, packet corrupted")
	ErrUnsupportedVersion = errors.New("binmodel: unsupported protocol major version")
	ErrIncompletePacket   = errors.New("binmodel: buffer holds less than one full packet")
)

// envelopeFixedLen is magic(1) + major(1) + minor(1) + schemaID(1) +
// flags(1) + length(4) — everything before Body.
const envelopeFixedLen = 9

// WrapPacket frames a body (typically from Encoder2.Bytes()) as:
//
//	[magic 0xB2][major][minor][schemaID][flags][length uint32 BE][body...][crc16 lo][crc16 hi]
//
// schemaID should be the Schema.ID of whatever Schema produced body, so a
// receiver holding multiple Schemas can dispatch on that one byte with a
// plain switch — no lookup, no reflection. flags is caller-defined (e.g.
// bit 0 = "compressed", bit 1 = "encrypted"); pass 0 if unused. length is
// len(body), which lets a stream reader consume exactly one packet and
// find the start of the next without scanning.
func WrapPacket(schemaID byte, body []byte, flags byte) []byte {
	out := make([]byte, 0, envelopeFixedLen+len(body)+2)
	out = append(out, PacketMagic, ProtocolVersionMajor, ProtocolVersionMinor, schemaID, flags)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	out = append(out, lenBuf[:]...)
	out = append(out, body...)
	crc := crc16CCITT(out)
	out = append(out, byte(crc), byte(crc>>8))
	return out
}

// UnwrapPacket validates and strips the envelope from the front of buf,
// returning the version, schema ID, flags, inner body, and how many bytes
// of buf the packet consumed (so a stream reader can slice buf[n:] to
// read the next one). It only requires buf to contain *at least* one full
// packet, not exactly one — trailing bytes are left for the caller.
func UnwrapPacket(buf []byte) (major, minor, schemaID, flags byte, body []byte, n int, err error) {
	if len(buf) < envelopeFixedLen+2 {
		return 0, 0, 0, 0, nil, 0, ErrShortHeader
	}
	if buf[0] != PacketMagic {
		return 0, 0, 0, 0, nil, 0, ErrBadMagic
	}
	major, minor, schemaID, flags = buf[1], buf[2], buf[3], buf[4]
	if major != ProtocolVersionMajor {
		return 0, 0, 0, 0, nil, 0, ErrUnsupportedVersion
	}

	length := binary.BigEndian.Uint32(buf[5:9])
	total := envelopeFixedLen + int(length) + 2
	if total > len(buf) {
		return 0, 0, 0, 0, nil, 0, ErrIncompletePacket
	}

	framed := buf[:total]
	payload := framed[:total-2]
	wantCRC := uint16(framed[total-2]) | uint16(framed[total-1])<<8
	if crc16CCITT(payload) != wantCRC {
		return 0, 0, 0, 0, nil, 0, ErrBadCRC
	}

	return major, minor, schemaID, flags, framed[envelopeFixedLen : total-2], total, nil
}

// crc16CCITT computes CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) —
// cheap enough for an MCU and standard enough that most UART/BLE stacks
// already have a hardware or library implementation to cross-check against.
func crc16CCITT(data []byte) uint16 {
	var crc uint16 = 0xFFFF
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// ---------------------------------------------------------------------
// Varint helpers (LEB128-style, unsigned) — small, branchless-ish, no strconv.
// ---------------------------------------------------------------------

func appendVarint(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}

func readVarint(b []byte) (value uint64, n int, err error) {
	var shift uint
	for i := 0; i < len(b); i++ {
		bt := b[i]
		value |= uint64(bt&0x7f) << shift
		if bt&0x80 == 0 {
			return value, i + 1, nil
		}
		shift += 7
		if shift > 63 {
			return 0, 0, ErrBadVarint
		}
	}
	return 0, 0, ErrShortHeader
}

// ---------------------------------------------------------------------
// Reflection-free hot path: implement these on your packet structs and
// skip reflection entirely. Safe for TinyGo / ESP32 / STM32.
// ---------------------------------------------------------------------

// BinMarshaler lets a struct encode itself directly into an Encoder2,
// with no reflection involved at all.
type BinMarshaler interface {
	MarshalBin(e *Encoder2) error
}

// BinUnmarshaler lets a struct populate itself from decoded fields,
// with no reflection involved at all.
type BinUnmarshaler interface {
	UnmarshalBin(fields []Field2) error
}

// MarshalFast encodes v (which must implement BinMarshaler) using schema.
// This is the recommended hot-path entry point — no reflect package is
// touched anywhere in this call.
func MarshalFast(schema *Schema, v BinMarshaler) ([]byte, error) {
	enc := NewEncoder2(schema)
	if err := v.MarshalBin(enc); err != nil {
		return nil, err
	}
	return enc.Bytes()
}

// UnmarshalFast decodes payload and hands the fields to v.UnmarshalBin.
func UnmarshalFast(schema *Schema, payload []byte, v BinUnmarshaler) error {
	fields, err := Decode2(schema, payload)
	if err != nil {
		return err
	}
	return v.UnmarshalBin(fields)
}

// BinMarshalerID / BinUnmarshalerID are the pure-numeric equivalents of
// BinMarshaler / BinUnmarshaler: no Schema needed for encode (field IDs
// are Go consts), and no Schema needed for decode either (DecodeIDs
// doesn't resolve names). This is what the code generator targets.
type BinMarshalerID interface {
	MarshalBinID(e *Encoder2) error
}

type BinUnmarshalerID interface {
	UnmarshalBinID(fields []FieldID) error
}

// MarshalFastID encodes v with no Schema lookup at all on the hot path;
// schema is only used for its ID (for WrapPacket) if you frame the result.
func MarshalFastID(v BinMarshalerID) ([]byte, error) {
	enc := &Encoder2{}
	if err := v.MarshalBinID(enc); err != nil {
		return nil, err
	}
	return enc.Bytes()
}

// UnmarshalFastID decodes payload with DecodeIDs (no Schema) and hands
// the raw fields to v.UnmarshalBinID.
func UnmarshalFastID(payload []byte, v BinUnmarshalerID) error {
	fields, err := DecodeIDs(payload)
	if err != nil {
		return err
	}
	return v.UnmarshalBinID(fields)
}

// ---------------------------------------------------------------------
// Example, hand-written (see cmd/bingen for the generated equivalent):
//
//	var relaySchema = MustSchema(3, "mailbox", "message", "time") // 3 = SchemaID
//
//	const (
//	    fieldMailbox = 1
//	    fieldMessage = 2
//	    fieldTime    = 3
//	)
//
//	type SendPacket struct {
//	    Mailbox []byte
//	    Message []byte
//	    Time    uint64
//	}
//
//	func (p *SendPacket) MarshalBinID(e *Encoder2) error {
//	    e.AddID(fieldMailbox, p.Mailbox)
//	    e.AddID(fieldMessage, p.Message)
//	    var scratch [8]byte
//	    _, err := e.AddUint64ID(fieldTime, p.Time, scratch[:])
//	    return err
//	}
//
//	func (p *SendPacket) UnmarshalBinID(fields []FieldID) error {
//	    for _, f := range fields {
//	        switch f.ID {
//	        case fieldMailbox:
//	            p.Mailbox = f.Data
//	        case fieldMessage:
//	            p.Message = f.Data
//	        case fieldTime:
//	            if len(f.Data) != 8 {
//	                return ErrShortBody
//	            }
//	            p.Time = binary.BigEndian.Uint64(f.Data)
//	        }
//	    }
//	    return nil
//	}
//
//	// send:
//	body, _ := MarshalFastID(&pkt)
//	framed := WrapPacket(relaySchema.ID, body, 0)
//
//	// receive:
//	_, _, schemaID, _, body, _, _ := UnwrapPacket(buf)
//	switch schemaID {
//	case relaySchema.ID:
//	    var pkt SendPacket
//	    _ = UnmarshalFastID(body, &pkt)
//	}
//
// Not one field-name string appears anywhere in MarshalBinID/UnmarshalBinID
// above — cmd/bingen generates exactly this from:
//
//	//bingen:schema id=3
//	type SendPacket struct {
//	    Mailbox []byte `bin:"1"`
//	    Message []byte `bin:"2"`
//	    Time    uint64 `bin:"3"`
//	}
