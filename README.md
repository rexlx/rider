# rider
udp / quic logging server. see tls_gen.sh for creating development certs. there is limited support for receiving syslog messages (udp only, no quic)

 ```bash
Usage of rider:
  -addr string
    	UDP/QUIC address to listen to (default ":5140")
  -api-token string
    	API Token (default "UmLPBz7zDXx1UreAJa+TupuBabP8T9wxr0yLTWiCnfQ=")
  -api-url string
    	API Endpoint for IOCs (default "http://localhost:8081/parse")
  -api-user string
    	API Username (default "test@aol.com")
  -hitslogfile string
    	Hits log file name (default "hits.json")
  -ioc
    	Enable real-time IOC parsing
  -logbackups int
    	Number of log file backups to keep (default 3)
  -logfile string
    	Log file name (default "structured.json")
  -logsize int
    	Max size of log file in MB (default 10)
  -prom-addr string
    	Address to expose Prometheus metrics (default ":9100")
  -queuesize int
    	Size of analysis buffer (default 10000)
  -size int
    	Size of the buffer (default 4096)
  -structured
    	Use structured logging (JSON) (default true)
  -tlscert string
    	Path to TLS certificate file for QUIC (default "server.crt")
  -tlskey string
    	Path to TLS key file for QUIC (default "server.key")
  -workers int
    	Number of analysis workers (default 4)
  -x	Experimental (QUIC mode)


go build .

sudo sysctl -w net.core.wmem_max=7500000;rider -addr ":5140" -x -tlscert ~/bin/data/server.crt -tlskey ~/bin/data/server.key -structured -ioc -api-token fbamZWsDYsaN8TxwkJW4g/NVttvaucWDsXhljF7N+38= -api-user test@aol.com -logbackups 10 -logsize 25
```
