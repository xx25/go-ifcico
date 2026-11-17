package ifcico

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// The loopback tests run the same constants on both ends, so they
// cannot notice a wrong one. These pin the wire as FTS-1024 writes it,
// in literal octets.

func TestWireSyncOctets(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, NewConn(&buf, nil).SendSync())
	assert.Equal(t, []byte{0xaa, 0x55}, buf.Bytes())

	// A peer's literal pair is accepted; a near miss is not.
	require.NoError(t, NewConn(bytes.NewBuffer([]byte{0xaa, 0x55}), nil).WaitSync(time.Now().Add(time.Second)))
	require.Error(t, NewConn(bytes.NewBuffer([]byte{0xaa, 0x56}), nil).WaitSync(time.Now().Add(time.Second)))
}

func TestWireCommandFrame(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, NewConn(&buf, nil).WriteCommand("SN"))
	assert.Equal(t, []byte{0xc6, 0x87, 0x00, 0x02, 'S', 'N', 0x6c}, buf.Bytes())

	ft, data, err := NewConn(bytes.NewBuffer([]byte{0xc6, 0x87, 0x00, 0x03, 'E', 'O', 'F', 0x6c}), nil).ReadFrame(time.Time{})
	require.NoError(t, err)
	assert.Equal(t, FrameCommand, ft)
	assert.Equal(t, []byte("EOF"), data)
}

func TestWireDataFrame(t *testing.T) {
	// 0x0102 = 258 data octets: the size field is big-endian.
	payload := bytes.Repeat([]byte{0x7e}, 258)
	var buf bytes.Buffer
	require.NoError(t, NewConn(&buf, nil).WriteFrame(FrameData, payload))
	want := append([]byte{0xc6, 0xe1, 0x01, 0x02}, payload...)
	want = append(want, 0x6c)
	assert.Equal(t, want, buf.Bytes())

	ft, data, err := NewConn(bytes.NewBuffer(want), nil).ReadFrame(time.Time{})
	require.NoError(t, err)
	assert.Equal(t, FrameData, ft)
	assert.Equal(t, payload, data)
}

func TestWireFrameSizeLimit(t *testing.T) {
	// 2048 (0x0800) is the largest legal data part; 2049 is refused on
	// read before any payload is consumed.
	ok := append([]byte{0xc6, 0xe1, 0x08, 0x00}, make([]byte, 2048)...)
	ok = append(ok, 0x6c)
	_, data, err := NewConn(bytes.NewBuffer(ok), nil).ReadFrame(time.Time{})
	require.NoError(t, err)
	require.Len(t, data, 2048)

	_, _, err = NewConn(bytes.NewBuffer([]byte{0xc6, 0xe1, 0x08, 0x01}), nil).ReadFrame(time.Time{})
	assert.True(t, err != nil && bytes.Contains([]byte(err.Error()), []byte("2048")), "got %v", err)
}

func TestWireSendCommand(t *testing.T) {
	// An odd timestamp goes out with its low bit cleared.
	cmd := formatSendCommand(&FileOffer{Name: "0000FFFF.MO1", Size: 4096, Timestamp: time.Unix(1700000001, 0)})
	assert.Equal(t, "S 0000FFFF.MO1 4096 1700000000", cmd)

	info, err := parseSendCommand("0000FFFF.MO1 4096 1700000000")
	require.NoError(t, err)
	assert.Equal(t, "0000FFFF.MO1", info.Name)
	assert.Equal(t, int64(4096), info.Size)
	assert.Equal(t, int64(1700000000), info.Timestamp.Unix())

	_, err = parseSendCommand("NAME.PKT -1 1700000000")
	require.Error(t, err)
}

type countingCloser struct {
	io.Reader
	closed int
}

func (c *countingCloser) Close() error { c.closed++; return nil }

type closeCountingWriter struct {
	bytes.Buffer
	closed int
}

func (w *closeCountingWriter) Close() error { w.closed++; return nil }

type oneFileReceiver struct {
	w    *closeCountingWriter
	info FileInfo
}

func (r *oneFileReceiver) Accept(info FileInfo) (RecvDecision, io.WriteCloser, int64) {
	r.info = info
	return AcceptROK, r.w, 0
}
func (r *oneFileReceiver) Progress(FileInfo, int64)    {}
func (r *oneFileReceiver) Done(FileInfo, int64, error) {}

// The offer's Close hook and the receiver's writer are each closed
// exactly once, and the timestamp crosses the wire in even seconds.
func TestBatchClosesOnceAndCarriesTheTimestamp(t *testing.T) {
	src := &countingCloser{Reader: bytes.NewReader([]byte("payload"))}
	sender := &fakeSender{offers: []*FileOffer{{
		Name: "A.PKT", Size: 7, Timestamp: time.Unix(1700000001, 0), Reader: src, Close: src.Close,
	}}}
	recv := &oneFileReceiver{w: &closeCountingWriter{}}

	errSend, errRecv := runBatch(t, sender, recv)
	require.NoError(t, errSend)
	require.NoError(t, errRecv)
	assert.Equal(t, 1, src.closed, "offer closed once")
	assert.Equal(t, 1, recv.w.closed, "writer closed once")
	assert.Equal(t, "payload", recv.w.String())
	assert.Equal(t, int64(1700000000), recv.info.Timestamp.Unix())
	assert.Equal(t, int64(7), recv.info.Size)
}

// The S command must fit one frame: 2048 octets is the last that does.
func TestValidateCommandLengthBoundary(t *testing.T) {
	offer := func(nameLen int) *FileOffer {
		return &FileOffer{Name: string(bytes.Repeat([]byte{'n'}, nameLen)), Size: 1, Timestamp: time.Unix(1700000000, 0), Reader: bytes.NewReader([]byte("x"))}
	}
	overhead := len(formatSendCommand(offer(1))) - 1
	fits := offer(MaxDataSize - overhead)
	assert.Equal(t, MaxDataSize, len(formatSendCommand(fits)))
	assert.NoError(t, fits.Validate())
	assert.Error(t, offer(MaxDataSize-overhead+1).Validate())
}
