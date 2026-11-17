package ifcico

import (
	"io"
	"time"
)

// FileOffer is what a Sender's NextFile returns: the metadata that
// goes into the FTS-1024 §5 "S <filename> <size> <timestamp>"
// command plus the Reader the data frames are sourced from.
//
// Reader is consumed start-to-finish on a successful send; if the
// receiver responds ROK with a non-zero offset, the sender skips
// that many bytes from the front of Reader before the first data
// frame. Close is optional and runs after the file is acked /
// errored / skipped.
//
// Name goes on the wire as one space-separated field: FTS-1024 expects
// a DOS 8.3 name, and a name containing whitespace cannot be carried.
// See Validate for the full rule; SendBatch reports an offer that fails
// it as SendAborted without sending anything, and carries on.
type FileOffer struct {
	Name      string
	Size      int64
	Timestamp time.Time
	Reader    io.Reader
	Close     func() error
}

// FileInfo is the receiver's view of an incoming file (the parsed
// fields of the "S" command). Timestamp is reconstructed from the
// wire as a Unix-seconds value; per §5 the sender rounds to even
// seconds.
type FileInfo struct {
	Name      string
	Size      int64
	Timestamp time.Time
}

// Sender is the application-side callback set the SendBatch FSM
// drives.
//
//   - NextFile returns the next FileOffer to send, or nil to finish
//     the batch (which transitions the FSM to S9/SN). An error ends
//     the batch at once and SendBatch returns it.
//   - Progress is called after every data frame (S6). bytesSent is
//     the position in the file: it starts at the resume offset, if
//     the receiver asked for one.
//   - Done is called exactly once for every offer NextFile returned,
//     with the verdict: SendOK (FOK), SendFERROR, SendSkipped (the
//     peer answered RS), or SendAborted — the offer failed Validate,
//     the peer answered RN, or the batch broke while this file was in
//     flight. For the last two SendBatch also returns an error.
//   - Done's bytesSent is the payload written for this file in this
//     batch, in completely written frames: 0 for a file that was
//     skipped or refused, the tail only for a resumed one, a partial
//     count for an abort. Note that it is NOT the position Progress
//     reports. peerNote says why on SendFERROR and SendAborted.
//
// After Done the library calls the offer's Close hook, once.
type Sender interface {
	NextFile() (*FileOffer, error)
	Progress(offer *FileOffer, bytesSent int64)
	Done(offer *FileOffer, outcome SendOutcome, bytesSent int64, peerNote string)
}

// Receiver is the application-side callback set the ReceiveBatch
// FSM drives.
//
//   - Accept inspects an incoming file's metadata and returns:
//   - decision: AcceptROK to receive (with optional resume offset),
//     SkipRS to acknowledge but discard, RefuseRN to terminate the
//     batch with an error.
//   - writer: where to stream payload when decision == AcceptROK.
//     Ignored otherwise; may be nil.
//   - offset: byte offset to start at (resume); spec encodes it in
//     the ROK command. Ignored for SkipRS / RefuseRN.
//   - Progress is called per data frame; bytesReceived counts what
//     arrived in this batch, from 0 — a resume offset is not added.
//   - Done runs once for every file Accept was asked about. err is
//     nil when the file was stored (FOK) and when it was skipped
//     (SkipRS, bytesReceived 0); it is ErrReceiverRefused for
//     RefuseRN, the write or close error when the verdict was FERROR,
//     and the I/O or protocol error when the batch broke mid-file.
type Receiver interface {
	Accept(info FileInfo) (decision RecvDecision, writer io.WriteCloser, offset int64)
	Progress(info FileInfo, bytesReceived int64)
	Done(info FileInfo, bytesReceived int64, err error)
}

// SendOutcome is the per-file delivery verdict the Sender's Done
// callback receives. The classes are the ones a mail queue needs:
// delivered, already there, and two shades of "send it again".
type SendOutcome int

const (
	// SendOK — peer responded FOK after EOF; file is delivered.
	SendOK SendOutcome = iota

	// SendFERROR — peer responded FERROR after EOF; §5 says the
	// sender "must mark the file as not transmitted so it can be
	// sent in another session" → retryable.
	SendFERROR

	// SendSkipped — peer responded RS to the S command; file is
	// already on the far side → clear from queue.
	SendSkipped

	// SendAborted — the file did not go through. Either it was started
	// and did not finish (carrier loss, write error mid-batch,
	// FSM-level error) — offer it again — or the offer failed
	// FileOffer.Validate, in which case offering the same thing again
	// fails the same way.
	SendAborted
)

// String returns a short token for log lines.
func (o SendOutcome) String() string {
	switch o {
	case SendOK:
		return "ok"
	case SendFERROR:
		return "ferror"
	case SendSkipped:
		return "skipped"
	case SendAborted:
		return "aborted"
	default:
		return "unknown"
	}
}

// RecvDecision is the Receiver's verdict on an incoming S command.
type RecvDecision int

const (
	// AcceptROK — receive the file (optionally from a non-zero
	// offset). Maps to ROK [<offset>] on the wire.
	AcceptROK RecvDecision = iota

	// SkipRS — already have it; acknowledge but discard. Maps to RS.
	SkipRS

	// RefuseRN — fatal; the receiver wants no more files this
	// batch. Maps to RN (the "fatal error" variant from §5 — not
	// the SN-ack variant). SendBatch surfaces this to the caller
	// as ErrPeerRefused.
	RefuseRN
)
