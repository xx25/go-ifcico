package ifcico

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// Errors specific to the receiver FSM.
var (
	// ErrInvalidSendCommand fires when an "S" command arrives without
	// its three fields (name, size, timestamp), or with a size or
	// timestamp that is not a number, or a negative size.
	// Per §6.3 R3 predicate 3 ("Garbage → Report → err") this is a
	// fatal-batch condition; the FSM stops and ReceiveBatch returns it.
	ErrInvalidSendCommand = errors.New("ifcico: malformed S command from peer")

	// ErrReceiverRefused fires when the application returned
	// RefuseRN from Accept — surfaces as a fatal-batch error since
	// §5 RN entry #1 says "the session should be terminated."
	ErrReceiverRefused = errors.New("ifcico: receiver refused with RN")
)

// ReceiveBatch runs the FTS-1024 §6.3 receiver automaton on c,
// routing incoming files through receiver. It logs to the logger c
// was built with.
//
// As with SendBatch, the function emits the leading sync pair (R0)
// and waits for the peer's pair (R1/R2) before entering R3. The
// loop terminates cleanly when an SN command arrives (R3 predicate
// 1 → R7) and unhealthy on any other R3 garbage / timeout
// predicate.
func ReceiveBatch(c *Conn, receiver Receiver) error {
	logger := c.log

	// R0: emit our sync pair.
	if err := c.SendSync(); err != nil {
		return fmt.Errorf("ifcico: R0 send sync: %w", err)
	}
	// R1/R2: wait for peer's sync pair.
	if err := c.WaitSync(time.Now().Add(DefaultCharTimeout)); err != nil {
		return fmt.Errorf("ifcico: R1/R2 wait sync: %w", err)
	}
	logger.Debug("ifcico: receiver sync exchange complete")

	// R3..R6: command loop.
	for {
		ft, data, err := c.ReadFrame(time.Now().Add(DefaultCharTimeout))
		if err != nil {
			return fmt.Errorf("ifcico: R3 wait command: %w", err)
		}
		if ft != FrameCommand {
			return fmt.Errorf("%w (R3: expected command, got data)", ErrUnexpectedFrame)
		}
		verb, arg := splitCommand(data)
		switch verb {
		case CmdSendNone:
			// R3 predicate 1: end of batch → R7.
			if err := c.WriteCommand(CmdReceiveNot); err != nil {
				return fmt.Errorf("ifcico: R7 ack SN: %w", err)
			}
			logger.Debug("ifcico: receiver batch complete")
			return nil
		case CmdSendFile:
			info, perr := parseSendCommand(arg)
			if perr != nil {
				return fmt.Errorf("ifcico: R3 parse S: %w", perr)
			}
			if err := receiveOneFile(c, info, receiver, logger); err != nil {
				return err
			}
		default:
			// R3 predicate 3: garbage → report → err.
			return fmt.Errorf("%w (R3: unknown verb %q)", ErrUnexpectedFrame, verb)
		}
	}
}

// receiveOneFile runs R4..R6 for one announced file.
func receiveOneFile(c *Conn, info FileInfo, receiver Receiver, logger *slog.Logger) error {
	// R4: application decision.
	decision, writer, offset := receiver.Accept(info)
	switch decision {
	case SkipRS:
		if err := c.WriteCommand(CmdReceiveSkip); err != nil {
			return fmt.Errorf("ifcico: R4 write RS: %w", err)
		}
		receiver.Done(info, 0, nil)
		return nil
	case RefuseRN:
		if err := c.WriteCommand(CmdReceiveNot); err != nil {
			return fmt.Errorf("ifcico: R4 write RN: %w", err)
		}
		receiver.Done(info, 0, ErrReceiverRefused)
		return ErrReceiverRefused
	case AcceptROK:
		// fall through to data-receive
	default:
		return fmt.Errorf("ifcico: R4 unknown RecvDecision %d", decision)
	}

	rok := CmdReceiveOK
	if offset > 0 {
		rok = fmt.Sprintf("%s %d", CmdReceiveOK, offset)
	}
	if err := c.WriteCommand(rok); err != nil {
		return fmt.Errorf("ifcico: R4 write ROK: %w", err)
	}

	// R5: receive data frames until EOF.
	var bytesReceived int64
	var writeErr error
	for {
		ft, data, err := c.ReadFrame(time.Now().Add(DefaultCharTimeout))
		if err != nil {
			closeWriter(writer)
			receiver.Done(info, bytesReceived, err)
			return fmt.Errorf("ifcico: R5 read frame: %w", err)
		}
		switch ft {
		case FrameData:
			if writeErr == nil && writer != nil {
				if _, werr := writer.Write(data); werr != nil {
					// Don't bail mid-batch — finish reading the
					// EOF so the peer's FSM stays aligned. We'll
					// flag FERROR at the verdict.
					writeErr = werr
				}
			}
			bytesReceived += int64(len(data))
			receiver.Progress(info, bytesReceived)
		case FrameCommand:
			verb, _ := splitCommand(data)
			if verb != CmdEOF {
				closeWriter(writer)
				receiver.Done(info, bytesReceived, fmt.Errorf("%w (R5: expected EOF, got %q)", ErrUnexpectedFrame, verb))
				return fmt.Errorf("%w (R5: expected EOF, got %q)", ErrUnexpectedFrame, verb)
			}
			// R5 predicate 2: EOF → R6.
			goto eof
		}
	}

eof:
	// R6: verdict. FOK if everything wrote cleanly, FERROR otherwise.
	if writer != nil {
		if cerr := writer.Close(); cerr != nil && writeErr == nil {
			writeErr = cerr
		}
	}
	if writeErr == nil {
		if err := c.WriteCommand(CmdFileOK); err != nil {
			receiver.Done(info, bytesReceived, err)
			return fmt.Errorf("ifcico: R6 write FOK: %w", err)
		}
		receiver.Done(info, bytesReceived, nil)
		logger.Debug("ifcico: receiver file ok", "name", info.Name, "bytes", bytesReceived)
	} else {
		if err := c.WriteCommand(CmdFileError); err != nil {
			receiver.Done(info, bytesReceived, err)
			return fmt.Errorf("ifcico: R6 write FERROR: %w", err)
		}
		receiver.Done(info, bytesReceived, writeErr)
		logger.Warn("ifcico: receiver file FERROR", "name", info.Name, "bytes", bytesReceived, "error", writeErr)
	}
	return nil
}

// parseSendCommand pulls (name, size, timestamp) out of the
// argument string of an "S" command. §5 specifies space separation
// and a Unix-seconds timestamp.
//
// Filenames in 8.3 form do not contain spaces, so a naive
// space-split is safe per the spec. We tolerate adjacent multiple
// spaces.
func parseSendCommand(arg string) (FileInfo, error) {
	fields := strings.Fields(arg)
	if len(fields) < 3 {
		return FileInfo{}, fmt.Errorf("%w (need 3 fields, got %d)", ErrInvalidSendCommand, len(fields))
	}
	name := fields[0]
	size, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return FileInfo{}, fmt.Errorf("%w (bad size %q: %v)", ErrInvalidSendCommand, fields[1], err)
	}
	if size < 0 {
		return FileInfo{}, fmt.Errorf("%w (negative size %d)", ErrInvalidSendCommand, size)
	}
	tsRaw, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return FileInfo{}, fmt.Errorf("%w (bad timestamp %q: %v)", ErrInvalidSendCommand, fields[2], err)
	}
	return FileInfo{
		Name:      name,
		Size:      size,
		Timestamp: time.Unix(tsRaw, 0).UTC(),
	}, nil
}

// closeWriter swallows the close error; the per-file verdict path
// has already captured whatever it cares about. A nil writer is
// fine.
func closeWriter(w io.WriteCloser) {
	if w == nil {
		return
	}
	_ = w.Close()
}
