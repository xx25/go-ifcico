# ifcico

Pure Go implementation of the FTS-1024 "raw ifcico" file-transfer protocol — the batch protocol FidoNet mailers run after an EMSI handshake selects the `TCP` compatibility code on a reliable (TCP-style) connection.

This is a library package — there is no CLI. Users import the `ifcico` package, wrap a connection in a `Conn`, and provide a `Sender` and/or `Receiver` to drive a batch in each direction.

The protocol is defined by FTS-1024 (FTSC). The package covers the frame format (§4), the command set (§5) and the two batch automata (§6.2 sender, §6.3 receiver). The EMSI handshake that precedes it is not part of this package.

## Features

- Frame layer over any `io.ReadWriter`: `ReadFrame` / `WriteFrame` / `WriteCommand`, with the sync-octet exchange (`SendSync` / `WaitSync`) that opens every batch
- Sender automaton (`SendBatch`, states S0..S10) and receiver automaton (`ReceiveBatch`, R0..R7)
- Resume: the receiver may answer `ROK <offset>`; the sender skips that many bytes (the receiver's writer must already stand at that offset)
- Per-file verdicts a mail queue can act on — delivered (`FOK`), already there (`RS`), retry (`FERROR`, abort) — each with the bytes actually sent
- Receiver decisions per file: accept, skip, or refuse the rest of the batch (`RN`)
- Read deadlines when the underlying connection supports them (`net.Conn`): every wait for a frame or for the sync pair is bounded at 120 s. Writes carry no deadline of their own
- Bounds on what a peer may send: frames above 2048 data octets and zero-length frames are rejected
- Standard library only; no dependencies

## Install

```
go get github.com/xx25/go-ifcico
```

## Usage

A session is two batches on the same connection: the calling side sends first and then receives, the answering side receives first and then sends. Both use the same API.

```go
package main

import (
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/xx25/go-ifcico"
)

// outbox implements ifcico.Sender over a list of local files.
type outbox struct {
	paths []string
}

func (o *outbox) NextFile() (*ifcico.FileOffer, error) {
	if len(o.paths) == 0 {
		return nil, nil // nothing more: the batch ends with SN
	}
	path := o.paths[0]
	o.paths = o.paths[1:]
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &ifcico.FileOffer{
		Name:      st.Name(),
		Size:      st.Size(),
		Timestamp: st.ModTime(),
		Reader:    f,
		Close:     f.Close,
	}, nil
}

func (o *outbox) Progress(offer *ifcico.FileOffer, bytesSent int64) {}

func (o *outbox) Done(offer *ifcico.FileOffer, outcome ifcico.SendOutcome, bytesSent int64, peerNote string) {
	// SendOK and SendSkipped mean the peer has the file; anything else
	// means it did not get it (peerNote says why).
	log.Printf("sent %s: %s, %d bytes %s", offer.Name, outcome, bytesSent, peerNote)
}

// inbox implements ifcico.Receiver, storing files in a directory.
type inbox struct {
	dir string
}

func (i *inbox) Accept(info ifcico.FileInfo) (ifcico.RecvDecision, io.WriteCloser, int64) {
	// info.Name comes from the peer: never use it as a path unchecked.
	f, err := os.CreateTemp(i.dir, "in-*")
	if err != nil {
		return ifcico.RefuseRN, nil, 0
	}
	return ifcico.AcceptROK, f, 0
}

func (i *inbox) Progress(info ifcico.FileInfo, bytesReceived int64) {}

func (i *inbox) Done(info ifcico.FileInfo, bytesReceived int64, err error) {
	log.Printf("received %s: %d bytes, err=%v", info.Name, bytesReceived, err)
}

func main() {
	// The EMSI handshake that negotiates "TCP" happens before this
	// point and is not part of the package.
	nc, err := net.DialTimeout("tcp", "node.example.org:60179", 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	c := ifcico.NewConn(nc, nil) // nil logger: slog.Default()

	// Caller: send our batch, then receive theirs.
	if err := ifcico.SendBatch(c, &outbox{paths: os.Args[1:]}); err != nil {
		log.Fatal(err)
	}
	if err := ifcico.ReceiveBatch(c, &inbox{dir: os.TempDir()}); err != nil {
		log.Fatal(err)
	}
}
```

The answering side runs the same two calls in the opposite order: `ReceiveBatch`, then `SendBatch`.

## File names

FTS-1024 sends a file as `S <name> <size> <timestamp>`, fields separated by spaces, and expects DOS 8.3 names. A name containing whitespace cannot be carried. `SendBatch` does not put such an offer on the wire: an offer that fails `FileOffer.Validate` — an empty name, a name with whitespace or control characters, a name too long for one frame, a negative size, no `Reader` — is reported to `Sender.Done` as `SendAborted` with nothing sent, and the batch continues with the next file. To stop the batch instead, call `Validate` in your `NextFile` and return its error.

## Sentinel errors

| Error | Meaning |
|---|---|
| `ErrPeerRefused` | The peer answered an `S` command with `RN`: it accepts nothing more this batch |
| `ErrReceiverRefused` | Our `Receiver` returned `RefuseRN` |
| `ErrUnexpectedFrame` | The peer sent a frame the automaton has no transition for, or a resume offset outside the file |
| `ErrInvalidOffer` | Wrapped by `FileOffer.Validate`: the offer cannot be expressed as an `S` command |
| `ErrInvalidSendCommand` | A malformed `S` command arrived |
| `ErrSyncTimeout` | The peer's sync octets did not arrive in time |
| `ErrInvalidFrameStart`, `ErrInvalidFrameType`, `ErrInvalidFrameEnd` | The frame envelope is broken |
| `ErrZeroLengthFrame`, `ErrFrameTooLarge` | The frame's size field is outside 1..2048 |

All are matched with `errors.Is`. A wait that runs out mid-batch surfaces as the connection's own timeout error (`net.Error`, `Timeout() == true`), wrapped; only the opening sync wait has a sentinel.

## Security

- **File names come from the peer.** `FileInfo.Name` is whatever the remote side put in its `S` command. Sanitise it (or ignore it, as the example does) before using it in a path.
- **Sizes are announcements.** `FileInfo.Size` is not enforced against the data that follows; bound what you accept in your `Receiver`'s writer.
- **There is no authentication or encryption here.** Both belong to the layers around this one: the EMSI handshake authenticates, the transport protects.

## License

MIT — see [LICENSE](LICENSE).
