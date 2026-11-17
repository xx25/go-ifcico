package ifcico

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"
)

// The assertion helpers the tests use. assert reports and carries on;
// require stops the test. Kept to the handful this package needs so the
// module has no dependency outside the standard library.

type assertions struct{ fatal bool }

var (
	assert  = assertions{fatal: false}
	require = assertions{fatal: true}
)

func (a assertions) fail(t testing.TB, what string, msgAndArgs []any) bool {
	t.Helper()
	if len(msgAndArgs) > 0 {
		if format, ok := msgAndArgs[0].(string); ok {
			what += ": " + fmt.Sprintf(format, msgAndArgs[1:]...)
		} else {
			what += ": " + fmt.Sprint(msgAndArgs...)
		}
	}
	if a.fatal {
		t.Fatal(what)
	} else {
		t.Error(what)
	}
	return false
}

func (a assertions) Equal(t testing.TB, want, got any, msgAndArgs ...any) bool {
	t.Helper()
	if wb, ok := want.([]byte); ok {
		if gb, ok := got.([]byte); ok && (wb == nil) == (gb == nil) && bytes.Equal(wb, gb) {
			return true
		}
	} else if reflect.DeepEqual(want, got) {
		return true
	}
	return a.fail(t, fmt.Sprintf("not equal:\n  want: %#v\n  got:  %#v", want, got), msgAndArgs)
}

func (a assertions) True(t testing.TB, v bool, msgAndArgs ...any) bool {
	t.Helper()
	if v {
		return true
	}
	return a.fail(t, "should be true", msgAndArgs)
}

func (a assertions) NoError(t testing.TB, err error, msgAndArgs ...any) bool {
	t.Helper()
	if err == nil {
		return true
	}
	return a.fail(t, fmt.Sprintf("unexpected error: %v", err), msgAndArgs)
}

func (a assertions) Error(t testing.TB, err error, msgAndArgs ...any) bool {
	t.Helper()
	if err != nil {
		return true
	}
	return a.fail(t, "an error is expected", msgAndArgs)
}

func (a assertions) Len(t testing.TB, v any, n int, msgAndArgs ...any) bool {
	t.Helper()
	if got := reflect.ValueOf(v).Len(); got != n {
		return a.fail(t, fmt.Sprintf("length %d, want %d: %#v", got, n, v), msgAndArgs)
	}
	return true
}

func (a assertions) Empty(t testing.TB, v any, msgAndArgs ...any) bool {
	t.Helper()
	rv := reflect.ValueOf(v)
	if !rv.IsValid() || rv.IsZero() {
		return true
	}
	switch rv.Kind() {
	case reflect.Slice, reflect.Map, reflect.String, reflect.Array, reflect.Chan:
		if rv.Len() == 0 {
			return true
		}
	}
	return a.fail(t, fmt.Sprintf("should be empty: %#v", v), msgAndArgs)
}

func (a assertions) NotNil(t testing.TB, v any, msgAndArgs ...any) bool {
	t.Helper()
	if v != nil {
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func, reflect.Interface:
			if !rv.IsNil() {
				return true
			}
		default:
			return true
		}
	}
	return a.fail(t, "should not be nil", msgAndArgs)
}

// tcpPair returns a connected client/server pair over 127.0.0.1. Real
// TCP rather than net.Pipe: each side writes its sync pair before it
// reads, which deadlocks on an unbuffered pipe. The
// accept is bounded at two seconds; an Accept error fails the test
// rather than handing back a nil conn. The caller closes both.
func tcpPair(t testing.TB) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srvCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			errCh <- aerr
			return
		}
		srvCh <- c
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case server = <-srvCh:
	case aerr := <-errCh:
		client.Close()
		t.Fatalf("accept failed: %v", aerr)
	case <-time.After(2 * time.Second):
		client.Close()
		t.Fatal("accept timed out")
	}
	return client, server
}
