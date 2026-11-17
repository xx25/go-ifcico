// Package ifcico implements the raw ifcico file-transfer protocol
// described in FTS-1024 — the file-batch protocol that runs after an
// EMSI handshake selects the "TCP" compatibility code over a reliable
// (TCP-style) channel.
//
// Two layers live here:
//
//   - the frame format (FTS-1024 §4): a `0xc6 | type | len(2) | data |
//     0x6c` envelope on top of any io.ReadWriter, exposed via Conn /
//     ReadFrame / WriteFrame plus the SendSync / WaitSync sync-octet
//     helpers from §6.2/§6.3.
//
//   - the Send/Receive batch FSMs (§6.2 / §6.3): SendBatch drives the
//     S0..S10 sender automaton and ReceiveBatch drives R0..R7 on the
//     other end.
//
// The package depends on the standard library only. A caller supplies
// the connection and a Sender / Receiver; the package knows nothing
// about queues, spools or storage.
package ifcico

import "time"

// FrameType identifies what a frame carries (FTS-1024 §4).
type FrameType byte

const (
	// FrameCommand frames carry protocol commands (S, RS, RN, ROK,
	// EOF, FOK, FERROR, SN). The argument string follows the
	// command verb with single-space separators per §5.
	FrameCommand FrameType = 0x87

	// FrameData frames carry file payload, appended to the
	// currently-receiving file (or dropped if no file is open).
	FrameData FrameType = 0xe1
)

// Frame envelope bytes (FTS-1024 §4).
const (
	frameStart byte = 0xc6 // header sentinel
	frameEnd   byte = 0x6c // trailer sentinel
)

// Sync octets (FTS-1024 §6.2 S0/S1/S2 and §6.3 R0/R1/R2). Each side
// emits the pair before starting its half of the batch; each side
// waits up to 120s for the peer's pair before proceeding.
const (
	syncByte1 byte = 0xaa
	syncByte2 byte = 0x55
)

// Frame data-size envelope (FTS-1024 §4). The DATA part must be
// between 1 and 2048 octets. A SIZE field of 0 in a received header
// must cause the frame to be dropped and logged (§4 paragraph 5).
const (
	MinDataSize     = 1
	MaxDataSize     = 2048
	DefaultDataSize = 1024 // §4: "The standard implementation uses data blocks of 1024 octets."
	headerSize      = 4    // start + type + MSBlen + LSBlen
	trailerSize     = 1    // end
)

// DefaultCharTimeout is the 120 seconds FTS-1024 allows every wait
// (§4 final paragraph + the §6.2/§6.3 state tables: "120 seconds
// nothing → error"). It is applied as one deadline per wait — a whole
// frame, or the sync pair — not per character.
const DefaultCharTimeout = 120 * time.Second

// Protocol command verbs (FTS-1024 §5). Stored as strings rather
// than constants typed FrameType because they are command-frame
// payload, not frame headers.
const (
	CmdSendFile    = "S"      // "S <filename> <size> <timestamp>"
	CmdReceiveSkip = "RS"     // already have this file
	CmdReceiveNot  = "RN"     // answering S: refuse this and any further files; answering SN: the batch-end ack
	CmdReceiveOK   = "ROK"    // "ROK [<offset>]" — accept; optional resume offset
	CmdEOF         = "EOF"    // end-of-file marker
	CmdFileOK      = "FOK"    // file received without errors
	CmdFileError   = "FERROR" // file received with errors → sender retains for next session
	CmdSendNone    = "SN"     // no more files
)
