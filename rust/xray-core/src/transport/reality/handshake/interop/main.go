// Independent test server: uses this repository's pinned Go REALITY dependency.
// Build from the repository root. It listens only on loopback and exits on stdin EOF.
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
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

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/xtls/reality"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		panic("usage: reality-interop-server hybrid|x25519 [mldsa]")
	}
	group := tls.X25519MLKEM768
	if os.Args[1] == "x25519" {
		group = tls.X25519
	} else if os.Args[1] != "hybrid" {
		panic("invalid group")
	}
	signing, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.test"}, DNSNames: []string{"example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	// The target must have enough certificate-flight bytes for REALITY's 3309-byte
	// optional ML-DSA signature while preserving mirrored record sizes.
	certificate.ExtraExtensions = []pkix.Extension{{Id: []int{1, 3, 6, 1, 4, 1, 57264, 1}, Value: make([]byte, 4096)}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &signing.PublicKey, signing)
	must(err)
	target, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: signing}}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{group}, NextProtos: []string{"h2", "http/1.1"}, SessionTicketsDisabled: true})
	must(err)
	defer target.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(30 * time.Second))
				if err := conn.(*tls.Conn).Handshake(); err == nil {
					io.Copy(io.Discard, conn)
				}
			}()
		}
	}()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	must(err)
	conf := &reality.Config{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, Type: "tcp", Dest: target.Addr().String(), ServerNames: map[string]bool{"example.test": true}, PrivateKey: key.Bytes(), ShortIds: map[[8]byte]bool{{1, 1, 1, 1, 1, 1, 1, 1}: true}, MaxTimeDiff: time.Minute, SessionTicketsDisabled: true}
	var mldsaPublic []byte
	if len(os.Args) == 3 {
		if os.Args[2] != "mldsa" {
			panic("invalid extra argument")
		}
		public, private, err := mldsa65.GenerateKey(rand.Reader)
		must(err)
		mldsaPublic, err = public.MarshalBinary()
		must(err)
		conf.Mldsa65Key, err = private.MarshalBinary()
		must(err)
	}
	reality.DetectPostHandshakeRecordsLens(conf)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	defer listener.Close()
	must(json.NewEncoder(os.Stdout).Encode(map[string]string{"address": listener.Addr().String(), "public_key": hex.EncodeToString(key.PublicKey().Bytes()), "mldsa65_public_key": hex.EncodeToString(mldsaPublic)}))
	go func() { io.Copy(io.Discard, os.Stdin); listener.Close() }()
	for {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(25 * time.Second))
			conn, err := reality.Server(context.Background(), raw, conf)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			defer conn.Close()
			if err = conn.Handshake(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			io.Copy(conn, conn)
		}()
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
