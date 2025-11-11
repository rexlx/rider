# rider
udp / quic logging server. see tls_gen.sh for creating development certs. there is limited support for receiving syslog messages (udp only, no quic)

 ```bash
Usage of ./rider:
  -addr string
    	UDP/QUIC address to listen to (default ":5140")
  -logbackups int
    	Number of log file backups to keep (default 3)
  -logfile string
    	Log file name (default "structured.json")
  -logsize int
    	Max size of log file in MB (default 10)
  -size int
    	Size of the buffer (default 4096)
  -structured
    	Use structured logging (JSON) (default true)
  -tlscert string
    	Path to TLS certificate file for QUIC (default "server.crt")
  -tlskey string
    	Path to TLS key file for QUIC (default "server.key")
  -x	Experimental (QUIC mode)


# run with temporary buffer increases
sudo sysctl -w net.core.rmem_max=7500000;sudo sysctl -w net.core.wmem_max=7500000
go build .
./rider -addr ":5140" -x -tlscert ~/bin/data/server.crt -tlskey ~/bin/data/server.key
```
