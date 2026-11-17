package ifcico

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Errors specific to the sender FSM.
var (
	// ErrPeerRefused fires when the peer responded RN to one of our
	// S commands (FTS-1024 §5: "refuse this and any further files,
	// the session should be terminated"). Surfaced as a fatal-batch
	// error; the in-flight file's Done callback runs with
	// SendAborted, and any files NextFile would have returned next
	// are not attempted.
	ErrPeerRefused = errors.New("ifcico: peer refused with RN")

	// ErrInvalidOffer is what FileOffer.Validate wraps: the offer cannot
	// be expressed as an S command.
	ErrInvalidOffer = errors.New("ifcico: offer cannot go on the wire")

	// ErrUnexpectedFrame fires when the peer sends a frame that
	// doesn't fit the current sender FSM state — e.g. a data
	// frame during S5 (Ackfile), or a command we don't recognise
	// during S8 (Waitack).
	ErrUnexpectedFrame = errors.New("ifcico: unexpected frame from peer")
)

// SendBatch runs the FTS-1024 §6.2 sender automaton on c, pulling
// files from sender until sender.NextFile returns nil. It logs to the
// logger c was built with.
//
// The function emits the leading sync pair and waits for the peer's
// sync pair before any S command (S0..S2). It then walks
// S3..S10 — one file per outer loop iteration — and finishes with
// SN / RN-ack.
//
// On a Go-level error (I/O failure, FSM violation, peer RN), the
// in-flight file's Done callback receives SendAborted with the
// underlying error reflected in peerNote. Files that NextFile would
// have produced after the abort do not appear in any callback —
// SendBatch returns and the caller can reconcile.
func SendBatch(c *Conn, sender Sender) error {
	logger := c.log

	// S0: emit our sync pair.
	if err := c.SendSync(); err != nil {
		return fmt.Errorf("ifcico: S0 send sync: %w", err)
	}
	// S1/S2: wait for peer's sync pair, 120s relaxed timeout.
	if err := c.WaitSync(time.Now().Add(DefaultCharTimeout)); err != nil {
		return fmt.Errorf("ifcico: S1/S2 wait sync: %w", err)
	}
	logger.Debug("ifcico: sender sync exchange complete")

	// S3..S10: file loop.
	for {
		offer, err := sender.NextFile()
		if err != nil {
			return fmt.Errorf("ifcico: NextFile: %w", err)
		}
		if offer == nil {
			break // S3 predicate 2: all files sent → S9.
		}

		err = sendOneFile(c, offer, sender, logger)
		closeOffer(offer)
		if err != nil {
			return err
		}
	}

	// S9: send SN.
	if err := c.WriteCommand(CmdSendNone); err != nil {
		return fmt.Errorf("ifcico: S9 send SN: %w", err)
	}
	// S10: wait for RN ack. Timeout → batch error.
	ft, data, err := c.ReadFrame(time.Now().Add(DefaultCharTimeout))
	if err != nil {
		return fmt.Errorf("ifcico: S10 wait RN-ack: %w", err)
	}
	if ft != FrameCommand {
		return fmt.Errorf("%w (S10: expected command, got data)", ErrUnexpectedFrame)
	}
	verb, _ := splitCommand(data)
	if verb != CmdReceiveNot {
		return fmt.Errorf("%w (S10: expected RN, got %q)", ErrUnexpectedFrame, verb)
	}
	logger.Debug("ifcico: sender batch complete")
	return nil
}

// sendOneFile runs S4..S8 for a single FileOffer. Returns nil if
// the file was sent (FOK or FERROR) or skipped (RS). Returns a
// non-nil error if the FSM hit a fatal condition (RN, I/O failure,
// unexpected frame).
func sendOneFile(c *Conn, offer *FileOffer, sender Sender, logger *slog.Logger) error {
	// An offer the wire cannot carry never reaches it: the S command is
	// space-separated, so a bad name would be misread by the receiver
	// and cost the whole batch. The file is reported and the batch goes
	// on with the next one. A caller that would rather stop the batch
	// calls Validate itself and returns the error from NextFile.
	if err := offer.Validate(); err != nil {
		sender.Done(offer, SendAborted, 0, err.Error())
		logger.Warn("ifcico: sender refused an offer", "name", offer.Name, "error", err)
		return nil
	}
	// S4: emit "S <name> <size> <timestamp>".
	cmd := formatSendCommand(offer)
	if err := c.WriteCommand(cmd); err != nil {
		sender.Done(offer, SendAborted, 0, "write S: "+err.Error())
		return fmt.Errorf("ifcico: S4 write S: %w", err)
	}

	// S5: wait for RS / RN / ROK.
	ft, data, err := c.ReadFrame(time.Now().Add(DefaultCharTimeout))
	if err != nil {
		sender.Done(offer, SendAborted, 0, "read S5 response: "+err.Error())
		return fmt.Errorf("ifcico: S5 read response: %w", err)
	}
	if ft != FrameCommand {
		sender.Done(offer, SendAborted, 0, "S5: expected command frame")
		return fmt.Errorf("%w (S5: expected command, got data)", ErrUnexpectedFrame)
	}
	verb, arg := splitCommand(data)
	switch verb {
	case CmdReceiveSkip:
		// S5 predicate 1: peer already has it.
		sender.Done(offer, SendSkipped, 0, "")
		return nil
	case CmdReceiveNot:
		// S5 predicate 2: fatal. §5 "RN" entry #1 — session
		// terminates.
		sender.Done(offer, SendAborted, 0, "peer RN")
		return ErrPeerRefused
	case CmdReceiveOK:
		// S5 predicate 3: accept with optional offset.
		offset := int64(0)
		if arg != "" {
			parsed, perr := strconv.ParseInt(strings.TrimSpace(arg), 10, 64)
			if perr != nil {
				sender.Done(offer, SendAborted, 0, "bad ROK offset")
				return fmt.Errorf("ifcico: S5 bad ROK offset %q: %w", arg, perr)
			}
			offset = parsed
		}
		if offset < 0 || offset > offer.Size {
			sender.Done(offer, SendAborted, 0, "bad ROK offset")
			return fmt.Errorf("%w (S5: ROK offset %d outside 0..%d)", ErrUnexpectedFrame, offset, offer.Size)
		}
		return sendFileData(c, offer, offset, sender, logger)
	default:
		sender.Done(offer, SendAborted, 0, "S5: unknown verb "+verb)
		return fmt.Errorf("%w (S5: unknown verb %q)", ErrUnexpectedFrame, verb)
	}
}

// sendFileData runs S6..S8: stream data frames, send EOF, await
// FOK / FERROR.
func sendFileData(c *Conn, offer *FileOffer, offset int64, sender Sender, logger *slog.Logger) error {
	// Skip `offset` bytes from the front of offer.Reader for resume.
	if offset > 0 {
		if _, err := io.CopyN(io.Discard, offer.Reader, offset); err != nil {
			sender.Done(offer, SendAborted, 0, "seek to offset: "+err.Error())
			return fmt.Errorf("ifcico: S6 seek to offset %d: %w", offset, err)
		}
	}

	// S6: chunk the payload into ≤DefaultDataSize frames.
	bytesSent := offset
	buf := make([]byte, DefaultDataSize)
	for {
		n, rerr := offer.Reader.Read(buf)
		if n > 0 {
			if werr := c.WriteFrame(FrameData, buf[:n]); werr != nil {
				sender.Done(offer, SendAborted, bytesSent-offset, "write data frame: "+werr.Error())
				return fmt.Errorf("ifcico: S6 write data frame: %w", werr)
			}
			bytesSent += int64(n)
			sender.Progress(offer, bytesSent)
		}
		if rerr == io.EOF {
			break // S6 predicate 1: end of file → S7.
		}
		if rerr != nil {
			sender.Done(offer, SendAborted, bytesSent-offset, "read source: "+rerr.Error())
			return fmt.Errorf("ifcico: S6 read source: %w", rerr)
		}
	}

	// S7: send EOF.
	if err := c.WriteCommand(CmdEOF); err != nil {
		sender.Done(offer, SendAborted, bytesSent-offset, "write EOF: "+err.Error())
		return fmt.Errorf("ifcico: S7 write EOF: %w", err)
	}

	// S8: wait for FOK / FERROR.
	ft, data, err := c.ReadFrame(time.Now().Add(DefaultCharTimeout))
	if err != nil {
		sender.Done(offer, SendAborted, bytesSent-offset, "read S8 ack: "+err.Error())
		return fmt.Errorf("ifcico: S8 read ack: %w", err)
	}
	if ft != FrameCommand {
		sender.Done(offer, SendAborted, bytesSent-offset, "S8: expected command frame")
		return fmt.Errorf("%w (S8: expected command, got data)", ErrUnexpectedFrame)
	}
	verb, _ := splitCommand(data)
	switch verb {
	case CmdFileOK:
		sender.Done(offer, SendOK, bytesSent-offset, "")
		logger.Debug("ifcico: sender file ok", "name", offer.Name, "bytes", bytesSent)
		return nil
	case CmdFileError:
		sender.Done(offer, SendFERROR, bytesSent-offset, "peer FERROR")
		logger.Warn("ifcico: sender file FERROR", "name", offer.Name, "bytes", bytesSent)
		return nil
	default:
		sender.Done(offer, SendAborted, bytesSent-offset, "S8: unknown verb "+verb)
		return fmt.Errorf("%w (S8: unknown verb %q)", ErrUnexpectedFrame, verb)
	}
}

// Validate reports whether the offer can go on the wire, as an error
// wrapping ErrInvalidOffer when it cannot. FTS-1024 §5 separates the S
// command's fields with spaces and has no quoting, so the name must be
// one non-empty token without whitespace or control characters; the
// size must not be negative; the whole command must fit one frame; and
// there must be a Reader to send from. SendBatch applies it to every
// offer NextFile returns.
func (o *FileOffer) Validate() error {
	if o.Name == "" {
		return fmt.Errorf("%w: no name", ErrInvalidOffer)
	}
	for _, r := range o.Name {
		if r <= ' ' || r == 0x7f || unicode.IsSpace(r) {
			return fmt.Errorf("%w: name has whitespace or a control character", ErrInvalidOffer)
		}
	}
	if o.Size < 0 {
		return fmt.Errorf("%w: negative size", ErrInvalidOffer)
	}
	if len(formatSendCommand(o)) > MaxDataSize {
		return fmt.Errorf("%w: name too long for one frame", ErrInvalidOffer)
	}
	if o.Reader == nil {
		return fmt.Errorf("%w: no reader", ErrInvalidOffer)
	}
	return nil
}

// formatSendCommand renders the §5 "S <name> <size> <timestamp>"
// command. Timestamp is encoded as Unix seconds rounded DOWN to the
// nearest even second per §5 ("rounded up to even seconds" is
// FTS-1024's wording but the consistent interpretation across
// every implementation is "make the low bit zero" — we mask).
func formatSendCommand(o *FileOffer) string {
	ts := o.Timestamp.Unix()
	if ts < 0 {
		ts = 0
	}
	ts &^= 1 // mask the low bit so DOS-friendly receivers don't trip
	return fmt.Sprintf("%s %s %d %d", CmdSendFile, o.Name, o.Size, ts)
}

// splitCommand splits a command-frame payload into the verb and its
// (possibly empty) argument string. A null-terminator at the end of
// the verb or arg is stripped per §4 paragraph 4. Internal whitespace
// in arg is preserved.
func splitCommand(data []byte) (verb, arg string) {
	s := strings.TrimRight(string(data), "\x00")
	s = strings.TrimRight(s, "\r\n")
	idx := strings.IndexAny(s, " \t")
	if idx == -1 {
		return s, ""
	}
	return s[:idx], strings.TrimLeft(s[idx+1:], " \t")
}

// closeOffer runs the optional Close hook, swallowing the error
// (the file-level outcome already drove sender.Done).
func closeOffer(o *FileOffer) {
	if o == nil || o.Close == nil {
		return
	}
	_ = o.Close()
}
