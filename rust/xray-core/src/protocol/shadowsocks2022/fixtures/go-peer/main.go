// Test-only peer. Build from the repository root so go.mod selects the exact
// pinned sing-shadowsocks version. Never used by the Rust implementation.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func data(size int, response bool) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte(i % 251)
		if response {
			out[i] = 255 - out[i]
		}
	}
	return out
}

type handler struct{}

func (handler) NewConnection(_ context.Context, conn net.Conn, metadata M.Metadata) error {
	defer conn.Close()
	if metadata.Destination.String() != "example.org:443" {
		return errors.New("wrong destination")
	}
	request := make([]byte, 70017)
	if _, err := io.ReadFull(conn, request); err != nil {
		return err
	}
	if !bytes.Equal(request, data(len(request), false)) {
		return errors.New("request mismatch")
	}
	response := data(73031, true)
	// The pinned initial response method has a uint16 length; keep that first
	// write bounded, then exercise ordinary multi-record writes separately.
	if _, err := conn.Write(response[:113]); err != nil {
		return err
	}
	_, err := conn.Write(response[113:])
	return err
}

func (handler) NewPacketConnection(context.Context, N.PacketConn, M.Metadata) error {
	return errors.New("UDP is outside this TCP test")
}
func (handler) NewError(_ context.Context, err error) { fmt.Fprintln(os.Stderr, err) }

func run() error {
	if len(os.Args) < 4 {
		return errors.New("usage: go-peer server|client METHOD BASE64_PSK [ADDRESS]")
	}
	mode, method, password := os.Args[1], os.Args[2], os.Args[3]
	if mode == "server" {
		service, err := shadowaead_2022.NewServiceWithPassword(method, password, 60, handler{}, nil)
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		defer listener.Close()
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(15 * time.Second))
		fmt.Println(listener.Addr())
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		return service.NewConnection(context.Background(), conn, M.Metadata{})
	}
	if mode != "client" || len(os.Args) != 5 {
		return errors.New("invalid peer mode or address")
	}
	client, err := shadowaead_2022.NewWithPassword(method, password, nil)
	if err != nil {
		return err
	}
	raw, err := net.DialTimeout("tcp", os.Args[4], 15*time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(15 * time.Second))
	conn, err := client.DialConn(raw, M.ParseSocksaddr("example.org:443"))
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.Write(data(70017, false)); err != nil {
		return err
	}
	response := make([]byte, 73031)
	if _, err = io.ReadFull(conn, response); err != nil {
		return err
	}
	if !bytes.Equal(response, data(len(response), true)) {
		return errors.New("response mismatch")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
