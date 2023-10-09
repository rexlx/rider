# rider
 its not a syslog server, but it will log the syslog data you point at it (so long as that data is UDP :) ). Theres an experimental quic server for handling encryption / streams.

 ```
go build .

./rider [args]

Usage of ./rider:
  -addr string
    	UDP address to listen to (default ":514")
  -logfile string
    	Log file to write to (default "rider.log")
  -size int
    	Size of the buffer (default 1024)
  -x	Experimental (quic)
```
