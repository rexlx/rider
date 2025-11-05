package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/rexlx/logary"
)

var (
	addr         = flag.String("addr", ":514", "UDP address to listen to")
	logfile      = flag.String("logfile", "rider.log", "Log file to write to")
	size         = flag.Int("size", 1024, "Size of the buffer")
	experimental = flag.Bool("x", false, "Experimental (quic)")
)

type quicRequest struct {
	Addr string
	Data []byte
}

type UDPLogger struct {
	Mutex        *sync.RWMutex
	Addr         string
	MessageCache []string
	Log          *logary.Logger
}

func main() {
	flag.Parse()
	// logfile, err := os.OpenFile(*logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	jsonLogger, err := logary.NewLogger(logary.Config{
		Filename:   "structured.json",
		Structured: true,
		Level:      logary.DebugLevel,
		MaxSizeMB:  10,
		MaxBackups: 3,
	})
	if err != nil {
		panic(err)
	}
	mu := &sync.RWMutex{}
	mcache := make([]string, 100)

	udpLogger := &UDPLogger{Addr: *addr, Log: jsonLogger, Mutex: mu, MessageCache: mcache}
	if *experimental {
		udpLogger.receiveDataOverQUIC()
	} else {
		udpLogger.receiveDataOverUDP()
	}
}

func (u *UDPLogger) receiveDataOverUDP() {
	serverAddr, err := net.ResolveUDPAddr("udp", u.Addr)
	if err != nil {
		panic(err)
	}
	server, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		panic(err)
	}
	defer server.Close()
	buf := make([]byte, *size)
	for {
		n, _, err := server.ReadFromUDP(buf)
		if err != nil {
			panic(err)
		}

		u.AddToCache(buf[:n])

		go u.writeToLog(buf[:n])
	}
}

func (u *UDPLogger) writeToLog(data []byte) {
	u.Log.Debugf("%s", bytes.TrimRight(data, "\n"))
	// u.Log.Println(strings.TrimRight(string(data), "\n"))
}

func (u *UDPLogger) AddToCache(data []byte) {
	if len(u.MessageCache) > 99 {
		u.MessageCache = u.MessageCache[1:]
	}
	u.MessageCache = append(u.MessageCache, string(data))
}

func (u *UDPLogger) readFromQUIC(sess quic.Connection) {
	fmt.Println("Accepting stream...")
	// create a context with not timout
	ctx := context.Background()
	stream, err := sess.AcceptStream(ctx)
	if err != nil {
		panic(err)
	}
	defer stream.Close()
	fmt.Println("Accepted stream")
	buf := make([]byte, *size)
	for {
		var qr quicRequest
		n, err := stream.Read(buf)
		if err != nil {
			if err.Error() == "EOF" {
				fmt.Println("readFromQUIC: Client closed connection")
				break
			}
			fmt.Println("readFromQUIC: Error reading from stream", err)
			break
		}
		err = json.Unmarshal(buf[:n], &qr)
		if err != nil {
			if strings.Contains(string(buf[:n]), "|beat|") {
				continue
			}
			fmt.Println("readFromQUIC: Error unmarshalling", err)
			// continue
		}
		if qr.Addr != "" {
			fmt.Println("Received cache request from address", qr.Addr)
			u.writeCacheToQUIC(stream)
			continue
		}
		u.AddToCache(buf[:n])
		go u.writeToLog(buf[:n])
	}
}

func (u *UDPLogger) writeToQUIC(stream quic.Stream, data []byte) {
	_, err := stream.Write(data)
	if err != nil {
		panic(err)
	}
}

func (u *UDPLogger) writeCacheToQUIC(stream quic.Stream) {
	u.Mutex.RLock()
	defer u.Mutex.RUnlock()
	for _, msg := range u.MessageCache {
		u.writeToQUIC(stream, []byte(msg))
	}
	// let the client know we're done
	u.writeToQUIC(stream, []byte("|eof|"))
}

func (u *UDPLogger) receiveDataOverQUIC() {
	fmt.Println("Starting QUIC server")
	cfg := createTLSConfig()
	serverAddr, err := net.ResolveUDPAddr("udp", u.Addr)
	if err != nil {
		panic(err)
	}
	server, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		panic(err)
	}
	defer server.Close()

	listener, err := quic.Listen(server, cfg, nil)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	fmt.Println("Listening for QUIC connections")
	for {
		sess, err := listener.Accept(context.Background())
		fmt.Println("Accepted connection")
		if err != nil {
			panic(err)
		}
		go u.readFromQUIC(sess)
	}

}

func createTLSConfig() *tls.Config {
	// Load client cert
	cert, err := tls.LoadX509KeyPair("/Users/rxlx/bin/data/server.crt", "/Users/rxlx/bin/data/server.key")
	if err != nil {
		log.Fatal(err)
	}
	// Load CA cert
	caCert, err := os.ReadFile("/Users/rxlx/bin/data/ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	// Setup HTTPS client
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		NextProtos:   []string{"rider-protocol"},
	}
}
