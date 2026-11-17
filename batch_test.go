package ifcico

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- test doubles -------------------------------------------------

type fakeSender struct {
	offers []*FileOffer
	idx    int
	done   []doneRec
	mu     sync.Mutex
}

type doneRec struct {
	name    string
	outcome SendOutcome
	bytes   int64
	note    string
}

func (s *fakeSender) NextFile() (*FileOffer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idx >= len(s.offers) {
		return nil, nil
	}
	o := s.offers[s.idx]
	s.idx++
	return o, nil
}

func (s *fakeSender) Progress(_ *FileOffer, _ int64) {}

func (s *fakeSender) Done(o *FileOffer, outcome SendOutcome, bytesSent int64, note string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = append(s.done, doneRec{o.Name, outcome, bytesSent, note})
}

type capturedFile struct {
	info FileInfo
	buf  *bytes.Buffer
	err  error
}

type fakeReceiver struct {
	captured []*capturedFile
	mu       sync.Mutex
	// override Accept's decision per filename. Default = AcceptROK.
	overrides map[string]RecvDecision
	// override Accept's offset per filename. Default = 0.
	offsets map[string]int64
}

func newFakeReceiver() *fakeReceiver {
	return &fakeReceiver{overrides: map[string]RecvDecision{}, offsets: map[string]int64{}}
}

type bufWriteCloser struct{ *bytes.Buffer }

func (b *bufWriteCloser) Close() error { return nil }

func (r *fakeReceiver) Accept(info FileInfo) (RecvDecision, io.WriteCloser, int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if d, ok := r.overrides[info.Name]; ok && d != AcceptROK {
		// record an empty capture for visibility
		r.captured = append(r.captured, &capturedFile{info: info, buf: &bytes.Buffer{}})
		return d, nil, 0
	}
	cf := &capturedFile{info: info, buf: &bytes.Buffer{}}
	r.captured = append(r.captured, cf)
	return AcceptROK, &bufWriteCloser{cf.buf}, r.offsets[info.Name]
}

func (r *fakeReceiver) Progress(_ FileInfo, _ int64) {}

func (r *fakeReceiver) Done(info FileInfo, _ int64, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.captured {
		if c.info.Name == info.Name {
			c.err = err
			return
		}
	}
}

// runBatch runs SendBatch on a-side and ReceiveBatch on b-side in
// parallel over a loopback TCP pair, returning their errors and the
// receiver's captured set.
func runBatch(t *testing.T, sender Sender, receiver Receiver) (errSend, errRecv error) {
	t.Helper()
	a, b := tcpPair(t)
	t.Cleanup(func() { a.Close(); b.Close() })

	connA := NewConn(a, nil)
	connB := NewConn(b, nil)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); errSend = SendBatch(connA, sender) }()
	go func() { defer wg.Done(); errRecv = ReceiveBatch(connB, receiver) }()
	wg.Wait()
	return errSend, errRecv
}

// TestLoopback64K: a 64 KB file flows end-to-end via SendBatch +
// ReceiveBatch over loopback TCP and arrives byte-identical.
func TestLoopback64K(t *testing.T) {
	const size = 64 * 1024
	payload := make([]byte, size)
	_, err := rand.Read(payload)
	require.NoError(t, err)

	offer := &FileOffer{
		Name:      "test64k.zip",
		Size:      size,
		Timestamp: time.Unix(1700000000, 0),
		Reader:    bytes.NewReader(payload),
	}
	sender := &fakeSender{offers: []*FileOffer{offer}}
	receiver := newFakeReceiver()

	errSend, errRecv := runBatch(t, sender, receiver)
	require.NoError(t, errSend)
	require.NoError(t, errRecv)

	require.Len(t, receiver.captured, 1, "exactly one file captured")
	cf := receiver.captured[0]
	assert.Equal(t, "test64k.zip", cf.info.Name)
	assert.Equal(t, int64(size), cf.info.Size)
	assert.Equal(t, payload, cf.buf.Bytes(), "received bytes must match sent bytes")
	require.NoError(t, cf.err)

	require.Len(t, sender.done, 1)
	assert.Equal(t, SendOK, sender.done[0].outcome)
}

// TestLoopbackMultipleFiles pins that the FSM correctly cycles
// through S3..S8 for multiple files and emits the final SN/RN
// transition.
func TestLoopbackMultipleFiles(t *testing.T) {
	files := []struct {
		name string
		data []byte
	}{
		{"a.txt", []byte("hello world")},
		{"b.bin", bytes.Repeat([]byte{0xa5}, 3000)}, // crosses one frame boundary
		{"c.dat", bytes.Repeat([]byte{0x5a}, 1)},
	}
	var offers []*FileOffer
	for _, f := range files {
		offers = append(offers, &FileOffer{
			Name:      f.name,
			Size:      int64(len(f.data)),
			Timestamp: time.Unix(1700000000, 0),
			Reader:    bytes.NewReader(f.data),
		})
	}
	sender := &fakeSender{offers: offers}
	receiver := newFakeReceiver()

	errSend, errRecv := runBatch(t, sender, receiver)
	require.NoError(t, errSend)
	require.NoError(t, errRecv)

	require.Len(t, receiver.captured, len(files))
	for i, f := range files {
		assert.Equal(t, f.name, receiver.captured[i].info.Name)
		assert.Equal(t, f.data, receiver.captured[i].buf.Bytes())
	}
	require.Len(t, sender.done, len(files))
	for _, d := range sender.done {
		assert.Equal(t, SendOK, d.outcome)
	}
}

// TestLoopbackSkippedFile pins §5 RS / §6.2 S5 predicate 1: the
// receiver responds RS, sender records SendSkipped and moves on.
func TestLoopbackSkippedFile(t *testing.T) {
	offers := []*FileOffer{
		{Name: "old.zip", Size: 5, Timestamp: time.Unix(1700000000, 0), Reader: bytes.NewReader([]byte("five!"))},
		{Name: "new.zip", Size: 4, Timestamp: time.Unix(1700000000, 0), Reader: bytes.NewReader([]byte("data"))},
	}
	sender := &fakeSender{offers: offers}
	receiver := newFakeReceiver()
	receiver.overrides["old.zip"] = SkipRS

	errSend, errRecv := runBatch(t, sender, receiver)
	require.NoError(t, errSend)
	require.NoError(t, errRecv)

	require.Len(t, sender.done, 2)
	assert.Equal(t, SendSkipped, sender.done[0].outcome)
	assert.Equal(t, int64(0), sender.done[0].bytes, "a skipped file put nothing on the wire")
	assert.Equal(t, SendOK, sender.done[1].outcome)
	assert.Equal(t, int64(4), sender.done[1].bytes)

	// new.zip is the second captured file; its buf has the data.
	var newcap *capturedFile
	for _, c := range receiver.captured {
		if c.info.Name == "new.zip" {
			newcap = c
			break
		}
	}
	require.NotNil(t, newcap)
	assert.Equal(t, []byte("data"), newcap.buf.Bytes())
}

// TestLoopbackPeerRefusesRN pins §5 RN entry #1 / §6.2 S5 predicate
// 2: a receiver-side refusal terminates the batch. The sender's
// SendBatch returns ErrPeerRefused, the in-flight file gets
// SendAborted, and the never-attempted second file is not in
// sender.done at all.
func TestLoopbackPeerRefusesRN(t *testing.T) {
	offers := []*FileOffer{
		{Name: "bad.zip", Size: 4, Timestamp: time.Unix(1700000000, 0), Reader: bytes.NewReader([]byte("nope"))},
		{Name: "never.zip", Size: 4, Timestamp: time.Unix(1700000000, 0), Reader: bytes.NewReader([]byte("skip"))},
	}
	sender := &fakeSender{offers: offers}
	receiver := newFakeReceiver()
	receiver.overrides["bad.zip"] = RefuseRN

	errSend, errRecv := runBatch(t, sender, receiver)
	require.Error(t, errSend)
	assert.True(t, errors.Is(errSend, ErrPeerRefused), "want ErrPeerRefused, got %v", errSend)
	require.Error(t, errRecv)
	assert.True(t, errors.Is(errRecv, ErrReceiverRefused))

	require.Len(t, sender.done, 1, "only the in-flight file should appear in Done")
	assert.Equal(t, "bad.zip", sender.done[0].name)
	assert.Equal(t, SendAborted, sender.done[0].outcome)
}

// TestLoopbackFERROR pins §5 FERROR / §6.2 S8 predicate 2: a
// write failure on the receiver side surfaces as FERROR on the
// wire and SendFERROR on the sender's Done. The batch continues
// to the next file.
func TestLoopbackFERROR(t *testing.T) {
	offers := []*FileOffer{
		{Name: "bad.bin", Size: 5, Timestamp: time.Unix(1700000000, 0), Reader: bytes.NewReader([]byte("12345"))},
		{Name: "good.bin", Size: 3, Timestamp: time.Unix(1700000000, 0), Reader: bytes.NewReader([]byte("abc"))},
	}
	sender := &fakeSender{offers: offers}
	receiver := &erroringReceiver{
		fakeReceiver: newFakeReceiver(),
		failOn:       "bad.bin",
	}

	errSend, errRecv := runBatch(t, sender, receiver)
	require.NoError(t, errSend)
	require.NoError(t, errRecv)

	require.Len(t, sender.done, 2)
	assert.Equal(t, SendFERROR, sender.done[0].outcome)
	assert.Equal(t, SendOK, sender.done[1].outcome)
}

// erroringReceiver wraps fakeReceiver and returns a writer that
// fails on Write for the named file — used by the FERROR test to
// drive §6.2 S8 predicate 2 through real protocol moves.
type erroringReceiver struct {
	*fakeReceiver
	failOn string
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("simulated disk full") }
func (failingWriter) Close() error              { return nil }

func (r *erroringReceiver) Accept(info FileInfo) (RecvDecision, io.WriteCloser, int64) {
	if info.Name == r.failOn {
		// Still record the capture for visibility.
		r.mu.Lock()
		r.captured = append(r.captured, &capturedFile{info: info, buf: &bytes.Buffer{}})
		r.mu.Unlock()
		return AcceptROK, failingWriter{}, 0
	}
	return r.fakeReceiver.Accept(info)
}

// TestLoopbackResume pins §5 ROK offset / §6.2 S5 predicate 3: the
// receiver requests a non-zero start offset and the sender skips
// that many bytes from the source.
func TestLoopbackResume(t *testing.T) {
	const offset = 5
	full := []byte("0123456789abcdef")
	offer := &FileOffer{
		Name:      "resume.bin",
		Size:      int64(len(full)),
		Timestamp: time.Unix(1700000000, 0),
		Reader:    bytes.NewReader(full),
	}
	sender := &fakeSender{offers: []*FileOffer{offer}}
	receiver := newFakeReceiver()
	receiver.offsets["resume.bin"] = offset

	errSend, errRecv := runBatch(t, sender, receiver)
	require.NoError(t, errSend)
	require.NoError(t, errRecv)

	require.Len(t, receiver.captured, 1)
	// Only bytes from `offset` onward should appear.
	assert.Equal(t, full[offset:], receiver.captured[0].buf.Bytes())
	assert.Equal(t, SendOK, sender.done[0].outcome)
	assert.Equal(t, int64(len(full))-offset, sender.done[0].bytes, "a resumed file reports the tail only")
}

// TestLoopbackEmptyBatch pins the "no files at all" path: SN goes
// out immediately, RN-ack comes back, both sides terminate clean.
func TestLoopbackEmptyBatch(t *testing.T) {
	sender := &fakeSender{}
	receiver := newFakeReceiver()
	errSend, errRecv := runBatch(t, sender, receiver)
	require.NoError(t, errSend)
	require.NoError(t, errRecv)
	assert.Empty(t, sender.done)
	assert.Empty(t, receiver.captured)
}

// TestUnsendableOfferIsReportedAndSkipped: an offer the S command
// cannot carry — a name with a space, no name, a negative size — never
// reaches the wire. It is reported SendAborted with nothing sent, its
// Close hook still runs, and the batch goes on with the next file.
func TestUnsendableOfferIsReportedAndSkipped(t *testing.T) {
	closed := 0
	bad := []*FileOffer{
		{Name: "my file.txt", Size: 4, Reader: bytes.NewReader([]byte("nope")), Close: func() error { closed++; return nil }},
		{Name: "", Size: 4, Reader: bytes.NewReader([]byte("nope"))},
		{Name: "tab\there", Size: 4, Reader: bytes.NewReader([]byte("nope"))},
		{Name: "neg.pkt", Size: -1, Reader: bytes.NewReader([]byte("nope"))},
		{Name: "noreader.pkt", Size: 4},
	}
	good := &FileOffer{Name: "good.pkt", Size: 4, Timestamp: time.Unix(1700000000, 0), Reader: bytes.NewReader([]byte("data"))}
	sender := &fakeSender{offers: append(bad, good)}
	receiver := newFakeReceiver()

	errSend, errRecv := runBatch(t, sender, receiver)
	require.NoError(t, errSend)
	require.NoError(t, errRecv)

	require.Len(t, sender.done, len(bad)+1)
	for i := range bad {
		assert.Equal(t, SendAborted, sender.done[i].outcome, "offer %d", i)
		assert.Equal(t, int64(0), sender.done[i].bytes, "offer %d", i)
		assert.True(t, sender.done[i].note != "", "offer %d carries a reason", i)
		assert.True(t, errors.Is(bad[i].Validate(), ErrInvalidOffer), "offer %d", i)
	}
	assert.Equal(t, SendOK, sender.done[len(bad)].outcome)
	assert.Equal(t, 1, closed, "the refused offer is still closed")
	require.Len(t, receiver.captured, 1)
	assert.Equal(t, "good.pkt", receiver.captured[0].info.Name)
	assert.Equal(t, []byte("data"), receiver.captured[0].buf.Bytes())
}

// TestValidateNames walks the name rule: one token, no whitespace of
// any kind (the receiver splits on Unicode spaces too), no control
// characters, and short enough for one frame.
func TestValidateNames(t *testing.T) {
	offer := func(name string) *FileOffer {
		return &FileOffer{Name: name, Size: 1, Reader: bytes.NewReader([]byte("x"))}
	}
	for _, name := range []string{
		"a b.pkt", "a\tb", "a\nb", "a\x00b", "a\x01b", "a\x7fb",
		"a\u00a0b", "a\u2003b", "a\u2028b", "a\u0085b",
		strings.Repeat("n", 2100),
	} {
		assert.True(t, errors.Is(offer(name).Validate(), ErrInvalidOffer), "%q must be refused", name)
	}
	for _, name := range []string{
		"0000FFFF.MO1", "nodelist.z01", "long-name_with.many.dots.tar.gz",
		"файл.zip", "a#b~c.pkt", strings.Repeat("n", 1900),
	} {
		assert.NoError(t, offer(name).Validate(), "%q must be accepted", name)
	}
	assert.NoError(t, (&FileOffer{Name: "empty.pkt", Size: 0, Reader: bytes.NewReader(nil)}).Validate())
}

// TestLoopbackEmptyFile: a zero-length file is a legal offer — S, ROK,
// EOF, FOK with no data frame in between.
func TestLoopbackEmptyFile(t *testing.T) {
	sender := &fakeSender{offers: []*FileOffer{{Name: "empty.pkt", Size: 0, Timestamp: time.Unix(1700000000, 0), Reader: bytes.NewReader(nil)}}}
	receiver := newFakeReceiver()
	errSend, errRecv := runBatch(t, sender, receiver)
	require.NoError(t, errSend)
	require.NoError(t, errRecv)
	require.Len(t, sender.done, 1)
	assert.Equal(t, SendOK, sender.done[0].outcome)
	assert.Equal(t, int64(0), sender.done[0].bytes)
	require.Len(t, receiver.captured, 1)
	assert.Equal(t, 0, receiver.captured[0].buf.Len())
}

// failAfter yields n bytes and then a read error.
type failAfter struct {
	n    int
	done bool
}

func (f *failAfter) Read(p []byte) (int, error) {
	if f.done {
		return 0, fmt.Errorf("simulated read failure")
	}
	f.done = true
	for i := 0; i < f.n; i++ {
		p[i] = 'x'
	}
	return f.n, nil
}

// TestAbortReportsThePartialCount: a source that fails mid-file aborts
// the batch, and Done carries what did go out. FERROR reports the whole
// file as sent — it was; the peer could not store it.
func TestAbortReportsThePartialCount(t *testing.T) {
	sender := &fakeSender{offers: []*FileOffer{{Name: "half.pkt", Size: 2000, Timestamp: time.Unix(1700000000, 0), Reader: &failAfter{n: 700}}}}
	// Not runBatch: the receiver would wait out its 120 s for the rest of
	// the file. Close the line as soon as the sender gives up.
	a, b := tcpPair(t)
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		_ = ReceiveBatch(NewConn(b, nil), newFakeReceiver())
	}()
	errSend := SendBatch(NewConn(a, nil), sender)
	a.Close()
	<-recvDone
	b.Close()
	require.Error(t, errSend)
	require.Len(t, sender.done, 1)
	assert.Equal(t, SendAborted, sender.done[0].outcome)
	assert.Equal(t, int64(700), sender.done[0].bytes)

	sender = &fakeSender{offers: []*FileOffer{{Name: "full.pkt", Size: 9, Timestamp: time.Unix(1700000000, 0), Reader: bytes.NewReader([]byte("ninebytes"))}}}
	errSend, errRecv := runBatch(t, sender, &erroringReceiver{fakeReceiver: newFakeReceiver(), failOn: "full.pkt"})
	require.NoError(t, errSend)
	require.NoError(t, errRecv)
	require.Len(t, sender.done, 1)
	assert.Equal(t, SendFERROR, sender.done[0].outcome)
	assert.Equal(t, int64(9), sender.done[0].bytes)
}

// TestResumeOffsetOutsideTheFileIsRefused: a peer's ROK offset must lie
// inside the file. A negative one or one past the end ends the batch
// with nothing sent.
func TestResumeOffsetOutsideTheFileIsRefused(t *testing.T) {
	for _, rok := range []string{"ROK -5", "ROK 11"} {
		a, b := tcpPair(t)
		go func() {
			defer b.Close()
			peer := NewConn(b, nil)
			_ = peer.SendSync()
			if peer.WaitSync(time.Now().Add(5*time.Second)) != nil {
				return
			}
			if _, _, err := peer.ReadFrame(time.Now().Add(5 * time.Second)); err != nil {
				return
			}
			_ = peer.WriteCommand(rok)
			_, _, _ = peer.ReadFrame(time.Now().Add(5 * time.Second))
		}()
		sender := &fakeSender{offers: []*FileOffer{{Name: "ten.pkt", Size: 10, Timestamp: time.Unix(1700000000, 0), Reader: bytes.NewReader([]byte("0123456789"))}}}
		err := SendBatch(NewConn(a, nil), sender)
		a.Close()
		assert.True(t, errors.Is(err, ErrUnexpectedFrame), "%s: got %v", rok, err)
		require.Len(t, sender.done, 1)
		assert.Equal(t, SendAborted, sender.done[0].outcome, rok)
		assert.Equal(t, int64(0), sender.done[0].bytes, rok)
	}
}
