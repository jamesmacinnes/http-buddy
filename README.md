# HTTP Buddy

## Demonstrates a simple multi-threaded non-blocking caching web server. 

### Usage:

```
./http-server [-p PORT -t Threads -c Connections -l LogLevel -r RootDir]

-p PORT: Port number to listen on, default 10000
-t Threads: Number of threads to run, default 1000
-c Connections: Number of concurrent connections, default 1000
-r RootDir: Document root for server, default current working directory
```
To build, just type "make".

See: https://paisleybuddy.com/blog/nonblocking-http-server-in-c for more information on this code.