// Independent interop fixture using this repository's Go XDRIVE transport.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/xdrive"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: xdrive-interop server|client local-folder")
	}
	settings := &internet.MemoryStreamConfig{ProtocolName: "xdrive", ProtocolSettings: &xdrive.Config{Service: "local", RemoteFolder: os.Args[2], SegmentBytes: 65536, FlushIntervalMs: 5, PollIntervalMs: 5, MaxPollIntervalMs: 20, SessionTtlSeconds: 5}}
	switch os.Args[1] {
	case "server":
		listener, err := xdrive.Serve(context.Background(), net.LocalHostIP, 0, settings, func(conn stat.Connection) {
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(20 * time.Second))
				if _, err := io.Copy(conn, conn); err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
			}()
		})
		must(err)
		defer listener.Close()
		fmt.Println("ready")
		io.Copy(io.Discard, os.Stdin)
	case "client":
		conn, err := xdrive.Dial(context.Background(), net.Destination{}, settings)
		must(err)
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(20 * time.Second))
		fmt.Println("ready")
		payload := make([]byte, 131071)
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		_, err = conn.Write(payload)
		must(err)
		received := make([]byte, len(payload))
		_, err = io.ReadFull(conn, received)
		must(err)
		if !bytes.Equal(payload, received) {
			panic("payload mismatch")
		}
		must(conn.Close())
	default:
		panic("invalid mode")
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
