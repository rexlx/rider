package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/quic-go/quic-go"
)

var (
	addr         = flag.String("addr", ":514", "UDP address to listen to")
	logfile      = flag.String("logfile", "rider.log", "Log file to write to")
	size         = flag.Int("size", 1024, "Size of the buffer")
	experimental = flag.Bool("x", false, "Experimental (quic)")
)

type UDPLogger struct {
	Addr string
	Log  *log.Logger
}

func main() {
	flag.Parse()
	logfile, err := os.OpenFile(*logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	defer logfile.Close()
	log := log.New(logfile, "", log.LstdFlags)
	udpLogger := &UDPLogger{Addr: *addr, Log: log}
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
		// get rid of trailing \n

		go u.writeToLog(buf[:n])
	}
}

func (u *UDPLogger) writeToLog(data []byte) {
	u.Log.Println(strings.TrimRight(string(data), "\n"))
}

func (u *UDPLogger) readFromQUIC(sess quic.Connection) {
	fmt.Println("Accepting stream...")
	stream, err := sess.AcceptStream(context.Background())
	if err != nil {
		panic(err)
	}
	defer stream.Close()
	fmt.Println("Accepted stream")
	buf := make([]byte, *size)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			panic(err)
		}
		go u.writeToLog(buf[:n])
	}
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
