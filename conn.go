package ifcico

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"
)

// Errors returned by the framer.
var (
	// ErrInvalidFrameStart fires when a received frame's leading byte
	// is not 0xc6 (FTS-1024 §4).
	ErrInvalidFrameStart = errors.New("ifcico: invalid frame start byte")

	// ErrInvalidFrameType fires for any Type field that is not
	// 0x87 (command) or 0xe1 (data).
	ErrInvalidFrameType = errors.New("ifcico: invalid frame type")

	// ErrInvalidFrameEnd fires when the trailing byte is not 0x6c.
	ErrInvalidFrameEnd = errors.New("ifcico: invalid frame end byte")

	// ErrZeroLengthFrame fires when a header advertises SIZE=0.
	// Per §4: "Upon receiving of a packet header with the SIZE field
	// set to 0, the total length of the incoming packet must be
	// treated as 5, this packet must be dropped, and the event
	// should be logged."
	ErrZeroLengthFrame = errors.New("ifcico: received frame with SIZE=0 (dropped)")

	// ErrFrameTooLarge fires when SIZE > MaxDataSize.
	ErrFrameTooLarge = errors.New("ifcico: received frame exceeds 2048-byte data limit")

	// ErrSyncTimeout fires when WaitSync does not see the peer's sync
	// within the configured deadline (FTS-1024 §6.2 S1/S2 / §6.3
	// R1/R2: "120 seconds nothing → error").
	ErrSyncTimeout = errors.New("ifcico: timeout waiting for sync octets")
)

// deadliner is what we type-assert the underlying io.ReadWriter
// against to enforce read deadlines. Both net.Conn and any wrapper
// that exposes SetReadDeadline satisfy it.
type deadliner interface {
	SetReadDeadline(t time.Time) error
}

// Conn carries the FTS-1024 frame envelope on top of any
// io.ReadWriter. When the underlying rw implements SetReadDeadline
// (net.Conn does), ReadFrame / WaitSync enforce the caller-supplied
// deadline at the OS level; otherwise the deadline is best-effort
// and the call may block indefinitely on an unresponsive peer.
//
// Conn is single-threaded — concurrent calls to ReadFrame /
// WriteFrame are not supported and the batch FSMs in send.go /
// recv.go don't need them.
type Conn struct {
	rw  io.ReadWriter
	dl  deadliner // nil if rw doesn't expose SetReadDeadline
	log *slog.Logger
}

// NewConn wraps rw with the FTS-1024 framer. Logger may be nil
// (treated as slog.Default()). The framer keeps no per-direction
// buffer beyond what's needed for the next frame, so a Conn can be
// safely composed with other read/write layers on the same rw.
func NewConn(rw io.ReadWriter, log *slog.Logger) *Conn {
	if log == nil {
		log = slog.Default()
	}
	c := &Conn{rw: rw, log: log}
	if d, ok := rw.(deadliner); ok {
		c.dl = d
	}
	return c
}

// SendSync emits the two-byte sync sequence 0xaa 0x55 that each side
// transmits before its half of the batch begins (FTS-1024 §6.2 S0 /
// §6.3 R0).
func (c *Conn) SendSync() error {
	_, err := c.rw.Write([]byte{syncByte1, syncByte2})
	if err != nil {
		return fmt.Errorf("ifcico: write sync octets: %w", err)
	}
	return nil
}

// WaitSync waits for the peer's 0xaa 0x55 sync pair, honouring the
// caller-supplied deadline (defaults to 120s if zero — the spec's
// relaxed-channel timeout). Garbage bytes received before the 0xaa
// are silently discarded per §6.2 S1 predicate 2 / §6.3 R1
// predicate 2 ("Received other → again").
//
// On a deadline-aware rw (net.Conn) the wait is enforced at the OS
// level; otherwise it's best-effort.
func (c *Conn) WaitSync(deadline time.Time) error {
	if deadline.IsZero() {
		deadline = time.Now().Add(DefaultCharTimeout)
	}
	if c.dl != nil {
		_ = c.dl.SetReadDeadline(deadline)
		defer func() { _ = c.dl.SetReadDeadline(time.Time{}) }()
	}

	state := 0 // 0 = waiting for 0xaa, 1 = waiting for 0x55
	buf := make([]byte, 1)
	for {
		if time.Now().After(deadline) {
			return ErrSyncTimeout
		}
		n, err := c.rw.Read(buf)
		if err != nil {
			// On a deadline-aware rw the OS surfaces the
			// deadline as a net.Error with Timeout()==true; we
			// translate that into the spec's "timeout" outcome.
			if isTimeout(err) {
				return ErrSyncTimeout
			}
			if n == 0 {
				return fmt.Errorf("ifcico: read sync octet: %w", err)
			}
		}
		if n == 0 {
			continue
		}
		switch state {
		case 0:
			if buf[0] == syncByte1 {
				state = 1
			}
			// any other byte: stay in state 0 (§6.2 S1 predicate 2)
		case 1:
			if buf[0] == syncByte2 {
				return nil
			}
			// §6.2 S2 predicate 2: "Received other → again" sends
			// us back to S1 (re-wait for 0xaa). We do NOT count
			// the wayward byte against the deadline reset — the
			// spec models S1 and S2 as separate states with their
			// own 120s clocks, but in practice a single overall
			// deadline is friendlier and simpler. If the peer is
			// genuinely garbling its sync, we'll fall out on the
			// outer time.Now().After check.
			state = 0
			if buf[0] == syncByte1 {
				// Spec doesn't explicitly handle "0xaa arrives
				// while we were waiting for 0x55" but treating
				// it as the start of a fresh sync pair is more
				// robust than dropping it. Stay in state 1.
				state = 1
			}
		}
	}
}

// ReadFrame reads one FTS-1024 frame, honouring deadline (default
// 120s when zero). Returns the FrameType and the DATA payload
// (length 1..2048). A zero-length frame is dropped per §4 and
// surfaces as ErrZeroLengthFrame so the caller can log and
// continue.
//
// The function consumes exactly one frame on success; on error the
// underlying rw is in an unspecified state and the connection
// should be abandoned (the spec offers no resync mechanism beyond
// the initial 0xaa/0x55 pair).
func (c *Conn) ReadFrame(deadline time.Time) (FrameType, []byte, error) {
	if deadline.IsZero() {
		deadline = time.Now().Add(DefaultCharTimeout)
	}
	if c.dl != nil {
		_ = c.dl.SetReadDeadline(deadline)
		defer func() { _ = c.dl.SetReadDeadline(time.Time{}) }()
	}

	hdr := make([]byte, headerSize)
	if err := readFull(c.rw, hdr); err != nil {
		return 0, nil, fmt.Errorf("ifcico: read frame header: %w", err)
	}
	if hdr[0] != frameStart {
		return 0, nil, fmt.Errorf("%w (got 0x%02x)", ErrInvalidFrameStart, hdr[0])
	}
	ft := FrameType(hdr[1])
	if ft != FrameCommand && ft != FrameData {
		return 0, nil, fmt.Errorf("%w (got 0x%02x)", ErrInvalidFrameType, hdr[1])
	}
	size := int(hdr[2])<<8 | int(hdr[3])
	if size == 0 {
		// §4: drop the frame (just the 5-byte envelope, no data
		// to skip) and log. The trailer still has to be consumed
		// off the wire so the connection stays aligned.
		tail := make([]byte, trailerSize)
		_ = readFull(c.rw, tail) // best effort; if this fails the conn is dead anyway
		c.log.Warn("ifcico: dropped frame with SIZE=0", "type", fmt.Sprintf("0x%02x", byte(ft)))
		return 0, nil, ErrZeroLengthFrame
	}
	if size > MaxDataSize {
		return 0, nil, fmt.Errorf("%w (size=%d)", ErrFrameTooLarge, size)
	}

	data := make([]byte, size)
	if err := readFull(c.rw, data); err != nil {
		return 0, nil, fmt.Errorf("ifcico: read frame data: %w", err)
	}
	tail := make([]byte, trailerSize)
	if err := readFull(c.rw, tail); err != nil {
		return 0, nil, fmt.Errorf("ifcico: read frame trailer: %w", err)
	}
	if tail[0] != frameEnd {
		return 0, nil, fmt.Errorf("%w (got 0x%02x)", ErrInvalidFrameEnd, tail[0])
	}
	return ft, data, nil
}

// WriteFrame emits one FTS-1024 frame with the supplied payload.
// data length must be in [MinDataSize, MaxDataSize]; callers
// chunking a large payload should split into ≤2048-byte frames
// (DefaultDataSize=1024 is the de-facto standard chunk size).
func (c *Conn) WriteFrame(ft FrameType, data []byte) error {
	if ft != FrameCommand && ft != FrameData {
		return fmt.Errorf("%w (got 0x%02x)", ErrInvalidFrameType, byte(ft))
	}
	size := len(data)
	if size < MinDataSize {
		return fmt.Errorf("ifcico: cannot write empty frame (spec disallows SIZE=0)")
	}
	if size > MaxDataSize {
		return fmt.Errorf("%w (got %d bytes)", ErrFrameTooLarge, size)
	}
	hdr := [headerSize]byte{frameStart, byte(ft), byte(size >> 8), byte(size & 0xff)}
	if _, err := c.rw.Write(hdr[:]); err != nil {
		return fmt.Errorf("ifcico: write frame header: %w", err)
	}
	if _, err := c.rw.Write(data); err != nil {
		return fmt.Errorf("ifcico: write frame data: %w", err)
	}
	if _, err := c.rw.Write([]byte{frameEnd}); err != nil {
		return fmt.Errorf("ifcico: write frame trailer: %w", err)
	}
	return nil
}

// WriteCommand is a convenience that frames a command-verb string
// as a FrameCommand. Empty commands are rejected (the spec
// forbids zero-length data).
func (c *Conn) WriteCommand(cmd string) error {
	if cmd == "" {
		return fmt.Errorf("ifcico: empty command")
	}
	return c.WriteFrame(FrameCommand, []byte(cmd))
}

// readFull is io.ReadFull with the error path normalised so
// EOF mid-read produces io.ErrUnexpectedEOF (which is what we
// want — a truncated frame is a protocol error, not "graceful
// end of stream").
func readFull(r io.Reader, p []byte) error {
	_, err := io.ReadFull(r, p)
	return err
}

// isTimeout reports whether err is a deadline-fired error from the
// net stack. Both net.OpError-wrapped errors and bare
// net.Error-implementing errors return Timeout()==true; we accept
// either shape.
func isTimeout(err error) bool {
	type timeoutErr interface {
		Timeout() bool
	}
	var te timeoutErr
	if errors.As(err, &te) {
		return te.Timeout()
	}
	return errors.Is(err, ErrSyncTimeout)
}
