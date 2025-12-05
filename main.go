package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rexlx/logary"
	"rxlx.us/rider/parser"
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

	// IOC Parsing Flags
	iocParsing  = flag.Bool("ioc", false, "Enable real-time IOC parsing")
	iocWorkers  = flag.Int("workers", 4, "Number of analysis workers")    // NEW FLAG
	queueSize   = flag.Int("queuesize", 10000, "Size of analysis buffer") // NEW FLAG
	apiURL      = flag.String("api-url", "http://localhost:8081/parse", "API Endpoint for IOCs")
	apiUser     = flag.String("api-user", "test@aol.com", "API Username")
	apiToken    = flag.String("api-token", "UmLPBz7zDXx1UreAJa+TupuBabP8T9wxr0yLTWiCnfQ=", "API Token")
	hitsLogFile = flag.String("hitslogfile", "hits.json", "Hits log file name")
)

// Thread-safe storage for IOC matches (Current Batch)
var (
	iocMatches = make(map[string]string) // Value -> Type
	iocMutex   sync.RWMutex
)

// Thread-safe storage for History (Already sent)
var (
	historyMatches = make(map[string]bool)
	historyMutex   sync.RWMutex
)

var hitsLogger *logary.Logger

type UDPLogger struct {
	Addr          string
	Log           *logary.Logger
	Parser        *parser.Contextualizer
	ParseIOCs     bool
	AnalysisQueue chan string // Channel to pass logs to workers
}

// Payload structure for the API request
type APIPayload struct {
	Username string `json:"username"`
	Blob     string `json:"blob"`
}

// Response structure from the API
type SummarizedEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	Matched       bool      `json:"matched"`
	Error         bool      `json:"error"`
	Background    string    `json:"background"`
	From          string    `json:"from"`
	ID            string    `json:"id"`
	AttrCount     int       `json:"attr_count"`
	Link          string    `json:"link"`
	ThreatLevelID int       `json:"threat_level_id"`
	Value         string    `json:"value"`
	Info          string    `json:"info"`
	RawLink       string    `json:"raw_link"`
	Type          string    `json:"type"`
}

func main() {
	flag.Parse()
	ignoreList := []string{"nullferatu.com"}
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

	var ctx *parser.Contextualizer
	var analysisQueue chan string

	if *iocParsing {
		ctx = parser.NewContextualizer(true, ignoreList, ignoreList)

		// Initialize the Buffered Channel
		analysisQueue = make(chan string, *queueSize)

		hitsLogger, err = logary.NewLogger(logary.Config{
			Filename:   *hitsLogFile,
			Structured: true,
			Level:      logary.InfoLevel,
			MaxSizeMB:  *logSize,
			MaxBackups: *logBackups,
		})
		if err != nil {
			panic(fmt.Errorf("failed to create hits logger: %v", err))
		}

		fmt.Printf("IOC Parsing enabled. Spawning %d workers. Sending batches to %s every 5s\n", *iocWorkers, *apiURL)

		// 1. Start the Worker Pool
		for i := 0; i < *iocWorkers; i++ {
			go analysisWorker(i, analysisQueue, ctx)
		}

		// 2. Start Ticker to flush and send IOCs
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				flushAndSendIOCs()
			}
		}()
	}

	udpLogger := &UDPLogger{
		Addr:          *addr,
		Log:           jsonLogger,
		Parser:        ctx,
		ParseIOCs:     *iocParsing,
		AnalysisQueue: analysisQueue,
	}

	if *experimental {
		fmt.Printf("Starting in QUIC mode on %s\n", *addr)
		udpLogger.receiveDataOverQUIC(*serverCert, *serverKey)
	} else {
		fmt.Printf("Starting in UDP mode on %s\n", *addr)
		udpLogger.receiveDataOverUDP()
	}
}

// NEW: The Worker Function
func analysisWorker(id int, queue <-chan string, p *parser.Contextualizer) {
	// Reusable buffer or local variables can go here to reduce GC pressure
	for logLine := range queue {
		for kind, regex := range p.Expressions {
			// This is CPU intensive, but now it runs on a different core
			matches := p.GetMatches(logLine, kind, regex)
			if len(matches) > 0 {
				iocMutex.Lock()
				for _, m := range matches {
					iocMatches[m.Value] = m.Type
				}
				iocMutex.Unlock()
			}
		}
	}
}

func flushAndSendIOCs() {
	iocMutex.Lock()
	if len(iocMatches) == 0 {
		iocMutex.Unlock()
		return
	}
	currentBatch := iocMatches
	iocMatches = make(map[string]string)
	iocMutex.Unlock()

	var matchesToSend []string

	historyMutex.Lock()
	for val := range currentBatch {
		if !historyMatches[val] {
			matchesToSend = append(matchesToSend, val)
			historyMatches[val] = true
		}
	}
	historyMutex.Unlock()

	if len(matchesToSend) == 0 {
		return
	}

	blob := strings.Join(matchesToSend, " ")
	fmt.Printf("[IOC Sender] Sending NEW batch of %d matches...\n", len(matchesToSend))

	payload := APIPayload{
		Username: *apiUser,
		Blob:     blob,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[IOC Sender] Error marshalling JSON: %v", err)
		return
	}

	req, err := http.NewRequest("POST", *apiURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		log.Printf("[IOC Sender] Error creating request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("%s:%s", *apiUser, *apiToken))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[IOC Sender] Request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var events []SummarizedEvent
		if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
			log.Printf("[IOC Sender] Error decoding response: %v", err)
			return
		}

		if len(events) > 0 {
			matchCount := 0
			for _, event := range events {
				if event.Matched {
					matchCount++
					fmt.Printf("   [MATCH] %s (%s) - ID: %s | Info: %s\n", event.Value, event.Type, event.ID, event.Info)
					if hitsLogger != nil {
						data, err := json.Marshal(event)
						if err == nil {
							hitsLogger.InfoJSON(data)
						}
					}
				}
			}
			if matchCount > 0 {
				fmt.Printf("[IOC Sender] Logged %d confirmed hits to %s\n", matchCount, *hitsLogFile)
			}
		}
	} else {
		log.Printf("[IOC Sender] API Error: %s", resp.Status)
	}
}

func (u *UDPLogger) writeToLog(data []byte) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return
	}

	logLine := string(trimmed)

	if strings.Contains(logLine, "action=DROP") && strings.Contains(logLine, "reason=POLICY-INPUT-GEN-DISCARD") {
		return
	}

	// 1. Write to Disk (Priority)
	if trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}' {
		u.Log.DebugJSON(trimmed)
	} else {
		u.Log.Debug(logLine)
	}

	// 2. Send to Analysis (Non-blocking)
	if u.ParseIOCs && u.AnalysisQueue != nil {
		select {
		case u.AnalysisQueue <- logLine:
			// Successfully queued for workers
		default:
			// Queue is full!
			// We skip analysis for this log to preserve ingestion speed.
			// Optional: Increment a "dropped_analysis" counter here.
		}
	}
}

// ... (receiveDataOverUDP and receiveDataOverQUIC remain the same)
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

	// This is the "Shared" buffer
	buf := make([]byte, *size)

	for {
		n, _, err := server.ReadFromUDP(buf)
		if err != nil {
			log.Printf("UDP Read Error: %v", err)
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])

		// Pass the COPY, not the original 'buf'
		u.writeToLog(payload)
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
			return
		}
		fmt.Println("Accepted new stream")
		go u.readFromStream(stream)
	}
}

func (u *UDPLogger) readFromStream(stream quic.Stream) {
	defer stream.Close()
	scanner := bufio.NewScanner(stream)

	for scanner.Scan() {
		// scanner.Bytes() is volatile!
		raw := scanner.Bytes()

		if bytes.Equal(bytes.TrimSpace(raw), []byte("|beat|")) {
			continue
		}

		payload := make([]byte, len(raw))
		copy(payload, raw)

		u.writeToLog(payload)
	}

	if err := scanner.Err(); err != nil {
		if err.Error() != "NO_ERROR" && err.Error() != "EOF" {
			log.Printf("Stream scan error: %v", err)
		}
	}
	fmt.Println("Stream closed")
}

func createTLSConfig(tlsCert, tlsKey string) *tls.Config {
	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		log.Fatal("Error loading server certs:", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"rider-protocol"},
	}
}
