package main

import (
	"flag"
	"log"
	"net"
	"os"
	"strings"
)

var (
	addr    = flag.String("addr", ":514", "UDP address to listen to")
	logfile = flag.String("logfile", "rider.log", "Log file to write to")
	size    = flag.Int("size", 1024, "Size of the buffer")
)

type UDPLogger struct {
	Addr string
	Log  *log.Logger
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

		u.Log.Println(strings.TrimRight(string(buf[0:n]), "\n"))
	}
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
	udpLogger.receiveDataOverUDP()
}
