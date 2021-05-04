/******************************************************************************
Copyright (C) 2021 Paisley Buddy Software (http://paisleybuddy.com)

http-buddy.c - Multi-threaded Caching Webserver

Demonstrates a simple multi-threaded non-blocking caching web server. 

Usage:

./http-buddy [-p PORT -t Threads -c Connections -l LogLevel -r RootDir]

-p PORT: Port number to listen on, default 10000
-t Threads: Number of threads to run, default 4
-c Connections: Number of concurrent connections, default 1000
-r RootDir: Document root for server, default current working directory

To build, type "make".

See: https://paisleybuddy.com/blog/nonblocking-http-server-in-c
 for more information on this code.

*****************************************************************************/
  /* Enbles thread safe versions of standard C functions. */
#define _REENTRANT

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/socket.h>
#include<sys/file.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<signal.h>
#include<fcntl.h>
#include<pthread.h>
#include<time.h>
#include<errno.h>
#include<sys/epoll.h>

  /* Default max connections. */
#define CONNMAX 1000

  /* File Read Buffer size. */
#define BYTES 10240

  /* Files larger than this will not be cached and will be rejected by
  the webserver if requested. */
#define MAXFILESIZE 512000000

  /* Default max threads. */
#define THREADMAX 4

  /* Default Port number. */
#define DEFAULTPORT "10000"

  /* The maximum size for a client's http request. */
#define MAXPAYLOAD 10240

  /* Error Severity defines. */
enum ErrorLog{LOG_ERROR, LOG_WARN, LOG_INFO};
const char *severityMessage[] = {"ERROR", "WARN", "INFO"};

  /* Request State definitions. */
enum RequestState{
    STATE_CONNECT, STATE_READ, 
    STATE_INDENTIFY, STATE_SEND,
    STATE_COMPLETE, STATE_ERROR};

  /* Max number of threads. */
long maxThreads = THREADMAX;

  /* The max number of concurrent connections. */
long maxConnections = CONNMAX;

  /* The http document root. */
char *rootDir;

  /* File descriptor for socket accept calls. */
int listenfd = 0;

  /* The listen port. */
const char *serverPort = DEFAULTPORT;

  /* Array of running threads. */
pthread_t *threads;

  /* Arrary of Epoll fds for each thread. */
int *socketEpoll;

  /* A node within a Hashtable. */
struct HashNodeStruct {
  char *key;
  char *value;
  long valueSize;
  struct HashNodeStruct *next;
};
typedef struct HashNodeStruct *HashNode;

  /* Holds an array of HashNodes. */
struct HashtableStruct {
  long size;
  struct HashNodeStruct **nodeArray;
};
typedef struct HashtableStruct *Hashtable;

  /* simple struct for holding basic elements of an http request. */
struct httpRequest {
  char host[160];
  char userAgent[1024];
};

  /* Hashtable that will hold the page cache. */
static Hashtable pages;

  /* The logging level. */
int logLevel = LOG_INFO;

typedef struct httpReadBufferStruct {
  char initialBuffer[MAXPAYLOAD];
  int bytesRead;
  int bytesToRead;
} httpReadBuffer, *httpReadBufferPtr;

typedef struct httpWriteBufferStruct {
  char *data;
  int size;
  int bytesWritten;
} httpWriteBuffer, *httpWriteBufferPtr;

typedef struct httpRequestResponseStruct {
  httpReadBufferPtr readBuffer;
  httpWriteBufferPtr writeBuffer;
  int state;
  int errorCode;
  int socket;
} httpRequestResponse, *httpRequestResponsePtr;

httpRequestResponsePtr httpRRArray;

  /* Function prototypes. */
void startServer(char *);
void *responseLoop(void *);
int respond(int , httpReadBufferPtr );
void logMessage(int, char *, int);
Hashtable createHashtable(long);
HashNode fromHash(Hashtable , char *);
int toHash(Hashtable , char *, char *, long);
void printUsage(char *prog);
const char *get_content_type(const char* );
void readRequest(httpRequestResponsePtr );
void identifyResource(httpRequestResponsePtr );
void sendResponse(httpRequestResponsePtr );

/******************************************************************************
 createHashtable() - Creates a Hashtable with an internal array size of "size"
 *****************************************************************************/
Hashtable createHashtable(long size) {
  Hashtable hash;

  hash = malloc(sizeof(struct HashtableStruct));
  hash->nodeArray = malloc(sizeof(struct HashNodeStruct) * size);
  memset(hash->nodeArray, 0, sizeof(struct HashNodeStruct) * size);
  hash->size = size;

  return hash;
}

/******************************************************************************
 getHashCode() - Simple fast hashing algorithm based on sdbm 
 (http://www.cse.yorku.ca/~oz/hash.html)
******************************************************************************/
unsigned long getHashCode(char *str) {
  unsigned long hash = 0;
  int c;

  while((c = *str++))
    hash = c + (hash << 6) + (hash << 16) - hash;

  return hash;
}

/******************************************************************************
fromHash() - Retrieves a value from a Hashtable. Returns a HashNode or NULL if 
key not found.
******************************************************************************/
HashNode fromHash(Hashtable hash, char *key) {
  struct HashNodeStruct *node = 
    hash->nodeArray[getHashCode(key) % hash->size];

  if(node && node->next == NULL) return node;

  while(node) {
    if(strcmp(key, node->key) == 0) return node;
    node = node->next;
  }
  return node;
}

/******************************************************************************
toHash() - Adds a byte array to the hash. "key" is a null terminated string.
Returns 1 on add, 2 on replace
*****************************************************************************/
int toHash(Hashtable hash, char *key, char *value, long valueSize) { 
  struct HashNodeStruct *node = malloc(sizeof(struct HashNodeStruct));
  memset(node, 0, sizeof(struct HashNodeStruct));

  unsigned long hashCode = getHashCode(key) % hash->size;

  struct HashNodeStruct *localnode = 
    hash->nodeArray[hashCode];

  while(localnode) { 

      /* Duplicate, replace. */
    if(strcmp(key, localnode->key) == 0) {
      free(localnode->value);
      localnode->value = value;
      localnode->valueSize = valueSize;

      return 2;
    }
    if(!localnode->next) break;
    localnode = localnode->next;
  }
  node->key = malloc(strlen(key) + 1);
  strcpy(node->key, key);
  node->value = value;
  node->valueSize = valueSize;
  node->next = NULL;

  if(localnode)
    localnode->next = node;
  else
    hash->nodeArray[hashCode] = node;

  return 1;
}

/******************************************************************************
 shutdownServer() - Clean up on shutdown
 *****************************************************************************/
void shutdownServer(int signum) {
  logMessage(LOG_INFO, "Shutting down.", 0);
  for(int i=0; i<maxConnections; i++) {
    if(httpRRArray[i].socket != -1) {
      shutdown(httpRRArray[i].socket, SHUT_RDWR);
      close(httpRRArray[i].socket);
    }
  }
  if(listenfd)
    close(listenfd);
    
  exit(0);
}

/******************************************************************************
 startServer() - Starts the socket listen process
 *****************************************************************************/
void startServer(char *port) {
  struct addrinfo hints, *res, *p;

    /* getaddrinfo for host */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  if(getaddrinfo(NULL, port, &hints, &res) != 0)
    logMessage(LOG_ERROR, strerror(errno), 0);

    /* Socket and bind */
  for(p=res; p!=NULL; p=p->ai_next) {
    listenfd = socket(p->ai_family, p->ai_socktype, 0);
    if(listenfd == -1) continue;
    int on = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, 
      (const char *) &on, sizeof(on));
    if(bind(listenfd, p->ai_addr, p->ai_addrlen) == 0) break;
  }
  if(p==NULL)
    logMessage(LOG_ERROR, strerror(errno), 0);

  freeaddrinfo(res);

    /* Listen for incoming connections. */
  if(listen(listenfd, 1000000) != 0)
    logMessage(LOG_ERROR, strerror(errno), 0);
}

/******************************************************************************
 initThreads() - Initializes response threads.
 *****************************************************************************/
void initThreads() {
  pthread_t tmpThread;

  threads = malloc(sizeof(unsigned long) * maxThreads);
  socketEpoll = malloc(sizeof(int) * maxThreads);
  httpRRArray = malloc(sizeof(httpRequestResponse) * maxConnections);
  for(int i=0; i<maxConnections; i++) {
    httpRRArray[i].readBuffer = malloc(sizeof(httpReadBuffer));
    httpRRArray[i].writeBuffer = malloc(sizeof(httpWriteBuffer));
  }

  for(int i=0;i<maxThreads;i++) {
    int *slot = malloc(sizeof(int)); // transfer i from local to global.
    *slot = i;
    socketEpoll[i] = epoll_create1(0);
    if(pthread_create(&tmpThread, NULL, responseLoop,  slot)) {
      logMessage(LOG_ERROR, strerror(errno), 0);
    }
  }
}

/******************************************************************************
 strnstr() - Find the first occurrence of find in s, where the search is 
 limited to the first slen characters of s.
 *****************************************************************************/
char *strnstr(const char *s, const char *find, size_t slen) {
  char c, sc;
  size_t len;

  if ((c = *find++) != '\0') {
    len = strlen(find);
    do {
      do {
        if (slen-- < 1 || (sc = *s++) == '\0')
          return (NULL);
      } while (sc != c);
      if (len > slen)
        return (NULL);
      } while (strncmp(s, find, len) != 0);
    s--;
  }
  return ((char *)s);
}

/******************************************************************************
 responseLoop() - Primary loop for the response threads. num is an offset
 into the various thread arrays.
*****************************************************************************/
void *responseLoop(void *num) {
  int n = *((int *) num);
  struct epoll_event *events;
  int nfds;
  httpRequestResponsePtr request;
  struct epoll_event ev;

  events = malloc(sizeof(struct epoll_event) * maxConnections);
  while(1) {
    nfds = epoll_wait(socketEpoll[n], events, maxConnections, -1);

    for(int i=0; i < nfds; i++) {
      int slot=events[i].data.fd;
      request = &httpRRArray[slot];
      switch(request->state) {
        case STATE_CONNECT:
          request->readBuffer->bytesRead = 0;
          request->readBuffer->bytesToRead = MAXPAYLOAD;
          readRequest(request);
          break;
        case STATE_READ:
          readRequest(request);
          break;
        case STATE_SEND:
          sendResponse(request);
          break;
      }
      if(request->state == STATE_COMPLETE || request->state == STATE_ERROR) {
        ev.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(socketEpoll[n], EPOLL_CTL_DEL, httpRRArray[slot].socket, &ev);
        shutdown(httpRRArray[slot].socket, SHUT_RDWR);
        close(httpRRArray[slot].socket);
        httpRRArray[slot].socket = -1;        
      }
    }
  }
}

/******************************************************************************
 readRequest() - Handles the http request

 States:
  Input: STATE_CONNECT, STATE_READ
  Output: STATE_READ, STATE_SEND, STATE_COMPLETE, STATE_ERROR
 *****************************************************************************/
void readRequest(httpRequestResponsePtr request) {
  request->state = STATE_READ;
  
  char *mesg = request->readBuffer->initialBuffer + 
    request->readBuffer->bytesRead;

  int rcvd=recv(request->socket, mesg, request->readBuffer->bytesToRead, 0);

  if(rcvd == -1) { // Socket Error!!!
    request->errorCode = errno;
    if(errno == EAGAIN || errno == EWOULDBLOCK) return;
    request->state = STATE_ERROR;
    return;
  }

  if(rcvd == 0) { // Unexpected close
    request->state = STATE_COMPLETE;
    return;
  }

  if(rcvd > 0) {
      /* Have we hit MAXPAYLOAD on the HTTP request. */
    if(request->readBuffer->bytesRead + rcvd >= MAXPAYLOAD) {
      if(write(request->socket, "HTTP/1.0 413 Payload Too Large\n", 31));
      logMessage(LOG_WARN, "Max Payload", request->socket);
      request->state = STATE_COMPLETE;
      return;
    }

    request->readBuffer->bytesRead += rcvd;
    request->readBuffer->bytesToRead -= rcvd;
    mesg[request->readBuffer->bytesRead] = 0;

      // Move to next State
    if(strnstr(request->readBuffer->initialBuffer, 
      "\r\n\r\n", request->readBuffer->bytesRead) != 0)
    {
      request->readBuffer->bytesToRead = 0;
      identifyResource(request);
    }
  }
}

/******************************************************************************
 identifyResource() - Handles the http request/response.

 States:
  Input: STATE_READ
  Output: STATE_SEND, STATE_COMPLETE, STATE_ERROR

 *****************************************************************************/
void identifyResource(httpRequestResponsePtr request) {
  char *mesg = request->readBuffer->initialBuffer;
  struct httpRequest header;
  char *token; 
  char *rest = mesg;
  char *reqline[3];
  char path[2048];
  char logBuffer[4096];
  char data_to_send[BYTES];
  int fd, bytesRead;

  request->state = STATE_INDENTIFY;

    /* Parse the request into a struct httpRequest. */
  while((token = strtok_r(rest, "\n", &rest))) {
    if(strncmp(token, "Host: ", 6) == 0) {
      int i=0;

      strcpy(header.host, token + 6);
      header.host[strlen(header.host)-1] = '\0';
      while(header.host[i++] != '\r') 
        if(header.host[i] == ':') {
          header.host[i]= '\0';
          break;
        }
    }
    if(strncmp(token, "User-Agent: ", 12) == 0) {
      strcpy(header.userAgent, token + 12);
    }
  }

  rest = mesg;
  reqline[0] = strtok_r(rest, " \t\n", &rest);

    /* Is a GET Request. */
  if(strncmp(reqline[0], "GET\0", 4)==0){
    reqline[1] = strtok_r(rest, " \t", &rest); 
    reqline[2] = strtok_r(rest, " \t\n", &rest);

    if(strncmp(reqline[2], "HTTP/1.0", 8)!=0 && 
      strncmp( reqline[2], "HTTP/1.1", 8)!=0 ) 
    {
      if(send(request->socket, "HTTP/1.0 400 Bad Request\n", 25, 0));
      request->state = STATE_COMPLETE;
      return;
    }

      /* Request is good. */
    strcpy(path, rootDir);

      /* Add index.html if url ends in '/' */
    if(reqline[1] && reqline[1][0] == '/' && 
      reqline[1][1] == '\0') 
    {
      reqline[1] = "/index.html";
      strcpy(&path[strlen(rootDir)], reqline[1]);
    } else strcpy(&path[strlen(rootDir)], reqline[1]);

      /* Check if file is already in the cache. */
    HashNode node = fromHash(pages, path);
    if(node) { 
      send(request->socket, "HTTP/1.0 200 OK\n\n", 17, 0);
      request->writeBuffer->data = node->value;
      request->writeBuffer->size = node->valueSize;
      request->writeBuffer->bytesWritten = 0;
      
      sendResponse(request);

      sprintf(logBuffer, "GET %s -- %s", path, header.userAgent);
      logMessage(LOG_INFO, logBuffer, request->socket);
    }
    else { /* Not in Cache, load from file and add to cache. */
      if((fd=open(path, O_RDONLY))!=-1) {
        struct stat fileInfo;
        fstat(fd, &fileInfo);

        long filesize = fileInfo.st_size;

          /* Error out on files that are larger than MAXFILESIZE */
        if(filesize > MAXFILESIZE) {
          send(request->socket, "HTTP/1.0 413 Payload Too Large\n", 31, 0);
          logMessage(LOG_WARN, "Max Payload", request->socket);
          request->state = STATE_COMPLETE;
          return;
        }
          /* Grab an exclusive lock on the file so only one thread 
          reads the file and creates a new page buffer. */ 
        flock(fd, LOCK_EX);

          /* Check that the file hasn't already been
          cached by another thread while waiting on file
          lock. */  
        node = fromHash(pages, path);
        if(node) {
          send(request->socket, "HTTP/1.0 200 OK\n\n", 17, 0);
          request->writeBuffer->data = node->value;
          request->writeBuffer->size = node->valueSize;
          request->writeBuffer->bytesWritten = 0;
          
          sendResponse(request);
          close(fd);
        } else { /* Have file lock and is uncached. */

          char *buffer;
          buffer = malloc(filesize);
          long size = 0;

            /* Load the file into a buffer then add to hash. */
          while((bytesRead=read(fd, data_to_send, BYTES)) > 0) {
              memcpy(buffer+size, data_to_send, bytesRead);
              size += bytesRead;
          }
          toHash(pages, path, buffer, size);
          close(fd);

          send(request->socket, "HTTP/1.0 200 OK\n\n", 17, 0);
          request->writeBuffer->data = buffer;
          request->writeBuffer->size = size;
          request->writeBuffer->bytesWritten = 0;
          
          sendResponse(request);
        }
        sprintf(logBuffer, 
          "GET %s -- %s", path, header.userAgent);
        logMessage(LOG_INFO, logBuffer, request->socket);
      }
      else { /* File not found. */
        send(request->socket, "HTTP/1.0 404 Not Found\n", 23, 0); 
        sprintf(logBuffer, "GET %s NOT FOUND" , path);
        logMessage(LOG_INFO, logBuffer, request->socket);
        request->state = STATE_COMPLETE;
      }
    }
  }
}

/******************************************************************************
 sendResponse() - Handles the http request/response.

 States:
  Input: STATE_IDENTIFYING, STATE_SEND
  Output: STATE_SEND, STATE_COMPLETE, STATE_ERROR

 *****************************************************************************/
void sendResponse(httpRequestResponsePtr request) {
  request->state = STATE_SEND;

  int len = send(request->socket, 
    request->writeBuffer->data + request->writeBuffer->bytesWritten, 
    request->writeBuffer->size, 0);

  if(len == -1) { // Socket Error!!!
    request->errorCode = errno;
    if(errno == EAGAIN || errno == EWOULDBLOCK) return;
    request->state = STATE_ERROR;
    return;
  }

  if(len > 0) {
    request->writeBuffer->bytesWritten += len;
    request->writeBuffer->size -= len;
    if(request->writeBuffer->size == 0) {
      request->state = STATE_COMPLETE;
    }
  }
}

/******************************************************************************
 *  logMessage() - Log messages
 *****************************************************************************/
void logMessage(int severity, char *string, int socket) {
  time_t now;
  struct tm  ts;
  char timeBuf[80];
  char clientip[30];
  int showLog = 0;

  switch(severity) {
    case LOG_ERROR:
      showLog = -1;
      break;

    case LOG_WARN:
      if(logLevel == 1 || logLevel == 2) showLog = 1;
      break;

    case LOG_INFO:
      if(logLevel == 2) showLog = 1;
      break;
  }
  if(showLog == 0) return;

  if(socket) {
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    getpeername(socket, (struct sockaddr *)&addr, &addr_size);

    strcpy(clientip, inet_ntoa(addr.sin_addr));
  }
  time(&now);
  ts = *localtime(&now);
  strftime(timeBuf, sizeof(timeBuf), "%a %Y-%m-%d %H:%M:%S %Z", &ts);
  
  if(socket)
    fprintf(stdout, "[%s] - %s - %s -- %s\n", 
      timeBuf, severityMessage[severity],
      clientip, string);
  else
    fprintf(stdout, "[%s] - %s - %s\n", 
      timeBuf, severityMessage[severity],
      string);

  if(showLog == -1) shutdownServer(0);
}

/******************************************************************************
 *  printUsage() - Print Help
 *****************************************************************************/
void printUsage(char *prog) {
  fprintf(stderr,
    "\n%s [-p PORT -t Threads -c Connections -l LogLevel -r RootDir]\n"
    "  -p PORT: Port number to listen on, default %s\n"
    "  -t Threads: Number of threads to run, default %ld\n"
    "  -c Connections: Number of concurrent connections, default %ld\n"
    "  -l LogLevel: 0 = off, 1 = WARN, 2 = INFO (full)\n"
    "  -r RootDir: Document root for server, default current working "
      "directory\n\n",
    prog, serverPort, maxThreads,maxConnections);
}

/******************************************************************************
 *  main()
 *****************************************************************************/
int main(int argc, char* argv[]) {
  struct sockaddr_in clientaddr;
  socklen_t addrlen;
  char c;
  int slot=0;

    /* Send SIGINT to shutdownServer */
  signal(SIGINT, shutdownServer); 

    /* Ignore SIGPIPE signals. */
  sigaction(SIGPIPE, &(struct sigaction){{SIG_IGN}}, NULL);

  char port[10];
  rootDir = getenv("PWD");
  strcpy(port, serverPort);
  maxConnections = CONNMAX;

    /* Parse the command line arguments */
  while ((c = getopt (argc, argv, "p:r:t:l:c:")) != -1)
    switch (c) {
      case 'r':
        rootDir = malloc(strlen(optarg));
        strcpy(rootDir, optarg);
        break;
      case 'p':
        strcpy(port, optarg);
        break;
      case 't':
        maxThreads = atoi(optarg);
        break;
      case 'l':
        logLevel = atoi(optarg);
        break;
      case 'c':
        maxConnections = atoi(optarg);
        break;
      case '?':
        printUsage(argv[0]);
        exit(1);
      default:
        exit(1);
    }

  pages = createHashtable(1000);
  if(chroot(rootDir));
  startServer(port);
  initThreads();

  for(int i=0; i<maxConnections; i++)
    httpRRArray[i].socket = -1;

  char buffer[1024];
  sprintf(buffer, 
    "Server started at port no. %s%s%s with %s%ld%s Connections, "
    "%s%ld%s Threads, rootDir directory as %s%s%s",
    "\033[92m",port,"\033[0m",
    "\033[92m",maxConnections,"\033[0m",
    "\033[92m",maxThreads,"\033[0m",
    "\033[92m",rootDir,"\033[0m");
  logMessage(LOG_INFO, buffer, 0);

  struct epoll_event ev;
  int pollSlot = 0;

  while (1) {
    addrlen = sizeof(clientaddr);
    httpRRArray[slot].socket = accept(listenfd, (struct sockaddr *) 
      &clientaddr, &addrlen);

    if (httpRRArray[slot].socket < 0) {
      if(errno != EAGAIN)
        logMessage(LOG_ERROR, strerror(httpRRArray[slot].socket), 0);
    }
    else {
      httpRRArray[slot].state = STATE_CONNECT;
      fcntl(httpRRArray[slot].socket, F_SETFL, 
        fcntl(httpRRArray[slot].socket, F_GETFL) | O_NONBLOCK);
      ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
      ev.data.fd = slot;
      epoll_ctl(socketEpoll[pollSlot], EPOLL_CTL_ADD, 
        httpRRArray[slot].socket, &ev);
      pollSlot = (pollSlot + 1) % maxThreads;
    }
      /* Loop around the httpRRArray array until a -1 is found. */
    while (httpRRArray[slot].socket != -1) slot = (slot + 1) % maxConnections;
  }
  return 0;
}