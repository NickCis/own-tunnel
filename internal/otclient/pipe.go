package otclient

import (
	"io"
	"sync"
)

// Pipe copies bidirectionally until both directions finish, propagating
// half-close where supported.
func Pipe(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		closeWrite(a)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		closeWrite(b)
	}()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

func closeWrite(c io.ReadWriteCloser) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// CloseWrite propagates a half-close when the writer supports it.
func CloseWrite(c io.ReadWriteCloser) {
	closeWrite(c)
}
