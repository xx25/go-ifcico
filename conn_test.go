package ifcico

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestFrameRoundTrip pins the most basic invariant: WriteFrame +
// ReadFrame round-trip a command frame and a data frame byte-for-byte
// over net.Pipe, with the FrameType preserved.
func TestFrameRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	sender := NewConn(a, nil)
	receiver := NewConn(b, nil)

	cases := []struct {
		name string
		ft   FrameType
		data []byte
	}{
		{"command", FrameCommand, []byte("S file.txt 12 1700000000")},
		{"data-1k", FrameData, bytes.Repeat([]byte{0x5a}, 1024)},
		{"data-max", FrameData, bytes.Repeat([]byte{0xa5}, MaxDataSize)},
		{"data-1", FrameData, []byte{0xff}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var wg sync.WaitGroup
			wg.Add(1)
			var werr error
			go func() {
				defer wg.Done()
				werr = sender.WriteFrame(tc.ft, tc.data)
			}()

			ft, data, err := receiver.ReadFrame(time.Now().Add(5 * time.Second))
			require.NoError(t, err)
			wg.Wait()
			require.NoError(t, werr)
			assert.Equal(t, tc.ft, ft)
			assert.Equal(t, tc.data, data)
		})
	}
}

// TestZeroLengthFrameDropped pins §4: a frame whose SIZE field is 0
// must be dropped with a logged event. We hand-craft the bytes (we
// can't make WriteFrame emit one — it refuses empty payloads).
func TestZeroLengthFrameDropped(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	// Hand-crafted zero-length frame: 0xc6 0x87 0x00 0x00 0x6c
	go func() {
		_, _ = a.Write([]byte{frameStart, byte(FrameCommand), 0x00, 0x00, frameEnd})
	}()

	receiver := NewConn(b, nil)
	_, _, err := receiver.ReadFrame(time.Now().Add(2 * time.Second))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrZeroLengthFrame), "expected ErrZeroLengthFrame, got %v", err)
}

// TestRejectInvalidFrameStart pins §4 envelope: a non-0xc6 leading
// byte aborts the frame read with ErrInvalidFrameStart.
func TestRejectInvalidFrameStart(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		_, _ = a.Write([]byte{0xff, byte(FrameCommand), 0x00, 0x02, 0x41, 0x42, frameEnd})
	}()

	receiver := NewConn(b, nil)
	_, _, err := receiver.ReadFrame(time.Now().Add(2 * time.Second))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidFrameStart), "expected ErrInvalidFrameStart, got %v", err)
}

// TestRejectInvalidFrameType pins §4: type 0x99 is neither command
// (0x87) nor data (0xe1).
func TestRejectInvalidFrameType(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		_, _ = a.Write([]byte{frameStart, 0x99, 0x00, 0x02, 0x41, 0x42, frameEnd})
	}()

	receiver := NewConn(b, nil)
	_, _, err := receiver.ReadFrame(time.Now().Add(2 * time.Second))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidFrameType))
}

// TestRejectInvalidFrameEnd pins §4: a frame ending in the wrong
// trailer byte is malformed.
func TestRejectInvalidFrameEnd(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		_, _ = a.Write([]byte{frameStart, byte(FrameCommand), 0x00, 0x02, 0x41, 0x42, 0xff})
	}()

	receiver := NewConn(b, nil)
	_, _, err := receiver.ReadFrame(time.Now().Add(2 * time.Second))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidFrameEnd))
}

// TestSyncRoundTrip pins §6.2/§6.3 S0..S2 / R0..R2: both sides send
// 0xaa 0x55, then each side observes the other's pair. Because
// net.Pipe is unbuffered (unlike real TCP), each direction runs in
// its own goroutine so Sends and Waits can interleave without
// deadlocking — over a buffered transport SendSync returns
// immediately and SendBatch / ReceiveBatch don't need this dance.
func TestSyncRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	side1 := NewConn(a, nil)
	side2 := NewConn(b, nil)

	var wg sync.WaitGroup
	wg.Add(4)
	var s1Send, s2Send, s1Wait, s2Wait error
	go func() { defer wg.Done(); s1Send = side1.SendSync() }()
	go func() { defer wg.Done(); s2Send = side2.SendSync() }()
	go func() { defer wg.Done(); s1Wait = side1.WaitSync(time.Now().Add(2 * time.Second)) }()
	go func() { defer wg.Done(); s2Wait = side2.WaitSync(time.Now().Add(2 * time.Second)) }()
	wg.Wait()
	require.NoError(t, s1Send)
	require.NoError(t, s2Send)
	require.NoError(t, s1Wait)
	require.NoError(t, s2Wait)
}

// TestSyncSkipsGarbage pins §6.2 S1 predicate 2 / S2 predicate 2:
// garbage bytes before the 0xaa 0x55 pair are silently discarded.
func TestSyncSkipsGarbage(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		_, _ = a.Write([]byte{0xff, 0x00, 0x12, syncByte1, syncByte2})
	}()
	receiver := NewConn(b, nil)
	require.NoError(t, receiver.WaitSync(time.Now().Add(2*time.Second)))
}

// TestSyncTimeout pins the 120s "received nothing" predicate by
// using a much shorter deadline (1ms): a connected-but-silent peer
// produces ErrSyncTimeout.
func TestSyncTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a // silent

	receiver := NewConn(b, nil)
	err := receiver.WaitSync(time.Now().Add(50 * time.Millisecond))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSyncTimeout), "want ErrSyncTimeout, got %v", err)
}

// TestWriteFrameRejectsEmpty pins the spec's SIZE>=1 invariant on
// the write side — we cannot serialise a zero-length data frame.
func TestWriteFrameRejectsEmpty(t *testing.T) {
	c := NewConn(&bytes.Buffer{}, nil)
	err := c.WriteFrame(FrameCommand, nil)
	require.Error(t, err)
}

// TestWriteFrameRejectsOversize pins MaxDataSize on the write side.
func TestWriteFrameRejectsOversize(t *testing.T) {
	c := NewConn(&bytes.Buffer{}, nil)
	err := c.WriteFrame(FrameData, bytes.Repeat([]byte{0}, MaxDataSize+1))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrFrameTooLarge))
}

// TestReadFrameWithoutDeadlineFallback pins the io.ReadWriter path:
// a wrapper that does NOT implement SetReadDeadline still round-trips
// frames; only the deadline guarantee weakens.
func TestReadFrameWithoutDeadlineFallback(t *testing.T) {
	buf := &bytes.Buffer{}
	c := NewConn(buf, nil)
	require.NoError(t, c.WriteFrame(FrameCommand, []byte("ROK")))
	ft, data, err := c.ReadFrame(time.Now().Add(time.Second))
	require.NoError(t, err)
	assert.Equal(t, FrameCommand, ft)
	assert.Equal(t, "ROK", string(data))
}

// TestReadFrameTruncatedSurfacesEOF pins the truncated-frame case:
// header arrives, data does not. io.ReadFull returns io.EOF when zero
// data bytes arrive (the "closed before any data" path) and
// io.ErrUnexpectedEOF when some but not all arrive. Either is an
// honest truncation report; the test accepts both rather than pinning
// a specific Go-stdlib choice that's easy to read but doesn't matter
// to the protocol contract.
func TestReadFrameTruncatedSurfacesEOF(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() {
		// header advertising 10 data bytes, then close → 0 arrive
		_, _ = a.Write([]byte{frameStart, byte(FrameData), 0x00, 0x0a})
		_ = a.Close()
	}()

	receiver := NewConn(b, nil)
	_, _, err := receiver.ReadFrame(time.Now().Add(2 * time.Second))
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF),
		"want EOF/ErrUnexpectedEOF, got %v", err)
}
