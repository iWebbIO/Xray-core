// A test-only pinned Go/uTLS REALITY client for the native Rust server.
// Build from the repository root:
// go build -o reality-go-client.exe ./rust/xray-core/src/transport/reality/handshake/server/interop
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	reality "github.com/xtls/xray-core/transport/internet/reality"
)

func run() error {
	if len(os.Args) != 4 {
		return fmt.Errorf("usage: reality-go-client ADDRESS PUBLIC_KEY_HEX SHORT_ID_HEX")
	}
	publicKey, err := hex.DecodeString(os.Args[2])
	if err != nil || len(publicKey) != 32 {
		return fmt.Errorf("invalid server public key")
	}
	shortID, err := hex.DecodeString(os.Args[3])
	if err != nil || len(shortID) != 8 {
		return fmt.Errorf("invalid short ID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", os.Args[1])
	if err != nil {
		return err
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	conn, err := reality.UClient(raw, &reality.Config{
		ServerName:  "example.test",
		PublicKey:   publicKey,
		ShortId:     shortID,
		Fingerprint: "chrome",
	}, ctx, xnet.TCPDestination(xnet.ParseAddress("example.test"), 443))
	if err != nil {
		return err
	}
	defer conn.Close()
	payload := []byte("pinned Go REALITY client to native Rust server")
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, received); err != nil {
		return err
	}
	if !bytes.Equal(received, payload) {
		return fmt.Errorf("incorrect echoed plaintext")
	}
	fmt.Println("OK")
	return nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "target" {
		if err := runTarget(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// A real Go TLS 1.3 target, not a second REALITY endpoint. The Rust server sees
// only its opaque first flight and deliberately never completes this connection.
func runTarget() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: reality-go-client target hybrid|x25519")
	}
	group := tls.X25519MLKEM768
	if os.Args[2] == "x25519" {
		group = tls.X25519
	} else if os.Args[2] != "hybrid" {
		return fmt.Errorf("invalid group")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{{Id: []int{1, 3, 6, 1, 4, 1, 57264, 1}, Value: make([]byte, 2048)}},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		return err
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}},
		MinVersion:   tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{group}, SessionTicketsDisabled: true,
	})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"address": listener.Addr().String()}); err != nil {
		return err
	}
	go func() { io.Copy(io.Discard, os.Stdin); listener.Close() }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return nil
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(15 * time.Second))
			conn.(*tls.Conn).Handshake()
		}()
	}
}
