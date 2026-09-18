// Package transport is the NexTalk runtime transport manager.
//
// Built NexTalk binaries discover, install, remove, enable, disable and
// update transports without recompiling the core. Transports are external
// OS processes speaking a length-prefixed NanoPack RPC over stdio
// (see rpc.go). They are untrusted: the RPC API cannot express private
// key material, and the FileRelay bridge uses the courier model
// (see docs/transport-runtime.md).
package transport

// TransportAPIVersion is the only runtime API version this core speaks.
// Transports declaring anything else are refused at initialize.
const TransportAPIVersion uint8 = 1
