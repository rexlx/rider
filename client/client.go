package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

type quicRequest struct {
	Addr string
	Data []byte
}

type SecretManager struct {
	QC          *quic.Config
	TC          *tls.Config
	Destination net.Addr
}

func dialQUIC(url string, sm *SecretManager) quic.Stream {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second) // 3s handshake timeout
	defer cancel()
	// fmt.Println("Dialing QUIC", url, sm.QC, sm.TC)
	conn, err := quic.DialAddr(ctx, url, sm.TC, sm.QC)
	if err != nil {
		log.Fatalln(err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Fatalln(err)
	}

	return stream
}

func SendAndReceiveOverQUIC(url string, sm *SecretManager, qr *quicRequest) {
	out, err := json.Marshal(qr)
	if err != nil {
		panic(err)
	}
	stream := dialQUIC(url, sm)
	defer stream.Close()
	// fmt.Println("Sending QUIC request")
	_, err = stream.Write(out)
	if err != nil {
		panic(err)
	}
	// fmt.Println("Reading QUIC response")
	data := make([]byte, 1024)
	for {
		var c int
		n, err := stream.Read(data)
		if err != nil {
			if err.Error() == "EOF" {
				// fmt.Println("Client closed connection")
				break
			}
			panic(err)
		}
		if string(data[:n]) == "|eof|" {
			// fmt.Println("Received EOF")
			break
		}
		c++
		// fmt.Println("Received data over QUIC")
		log.Println(string(data[:n]), c)
	}
}

func main() {
	sm := &SecretManager{
		QC: &quic.Config{},
		TC: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"rider-protocol"}},
	}
	qr := &quicRequest{
		Addr: "MARIO",
	}
	SendAndReceiveOverQUIC("localhost:4242", sm, qr)
}
