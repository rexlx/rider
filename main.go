package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/quic-go/quic-go"
	"github.com/rexlx/logary"
)

var (
	addr         = flag.String("addr", ":5140", "UDP/QUIC address to listen to")
	experimental = flag.Bool("x", false, "Experimental (QUIC mode)")
	size         = flag.Int("size", 4096, "Size of the buffer")
	logFile      = flag.String("logfile", "structured.json", "Log file name")
	logSize      = flag.Int("logsize", 10, "Max size of log file in MB")
	logBackups   = flag.Int("logbackups", 3, "Number of log file backups to keep")
	structured   = flag.Bool("structured", true, "Use structured logging (JSON)")
	serverCert   = flag.String("tlscert", "server.crt", "Path to TLS certificate file for QUIC")
	serverKey    = flag.String("tlskey", "server.key", "Path to TLS key file for QUIC")
	// logLevel     = flag.String("loglevel", "debug", "Log level (debug, info, warn, error)")
)

type UDPLogger struct {
	Addr string
	Log  *logary.Logger
}

func main() {
	flag.Parse()

	jsonLogger, err := logary.NewLogger(logary.Config{
		Filename:   *logFile,
		Structured: *structured,
		Level:      logary.DebugLevel,
		MaxSizeMB:  *logSize,
		MaxBackups: *logBackups,
	})
	if err != nil {
		panic(err)
	}

	udpLogger := &UDPLogger{
		Addr: *addr,
		Log:  jsonLogger,
	}

	if *experimental {
		fmt.Printf("Starting in QUIC mode on %s\n", *addr)
		udpLogger.receiveDataOverQUIC(*serverCert, *serverKey)
	} else {
		fmt.Printf("Starting in UDP mode on %s\n", *addr)
		udpLogger.receiveDataOverUDP()
	}
}

func (u *UDPLogger) writeToLog(data []byte) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return
	}
	// Log to file via logary
	u.Log.Debugf("%s", trimmed)
	// Also print to stdout for immediate feedback
	// fmt.Printf("[LOG] %s\n", string(trimmed))
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
			log.Printf("UDP Read Error: %v", err)
			continue
		}
		u.writeToLog(buf[:n])
	}
}

func (u *UDPLogger) receiveDataOverQUIC(tlsCert, tlsKey string) {
	cfg := createTLSConfig(tlsCert, tlsKey)
	udpAddr, err := net.ResolveUDPAddr("udp", u.Addr)
	if err != nil {
		panic(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		panic(err)
	}
	defer udpConn.Close()

	listener, err := quic.Listen(udpConn, cfg, nil)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	fmt.Println("Listening for QUIC connections...")
	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("QUIC Accept Error: %v", err)
			continue
		}
		fmt.Println("Accepted new QUIC connection")
		go u.handleQUICSession(sess)
	}
}

func (u *UDPLogger) handleQUICSession(sess quic.Connection) {
	for {
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			// Connection likely closed
			return
		}
		fmt.Println("Accepted new stream")
		go u.readFromStream(stream)
	}
}

func (u *UDPLogger) readFromStream(stream quic.Stream) {
	defer stream.Close()
	buf := make([]byte, *size)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			if err.Error() != "EOF" {
				// Only log actual errors, not normal stream closures
				// fmt.Printf("Stream read error: %v\n", err)
			}
			break
		}

		data := buf[:n]
		// Check for heartbeat from client
		if bytes.Equal(data, []byte("|beat|")) {
			fmt.Print(".") // Optional: print a dot for heartbeats
			continue
		}

		u.writeToLog(data)
	}
	fmt.Println("Stream closed")
}

func createTLSConfig(tlsCert, tlsKey string) *tls.Config {
	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		log.Fatal("Error loading server certs:", err)
	}
	// We don't strictly need the CA cert pool if we aren't verifying clients,
	// but keeping it if you intend to use mTLS later.
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"rider-protocol"},
	}
}
