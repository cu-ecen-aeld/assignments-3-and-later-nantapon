// Hi
#include <syslog.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <netdb.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>

static bool sig_recvd = false;

static void sighandler(int x)
{
  sig_recvd = true;
}

static bool read_packet(int sock, int fd)
{
  char buffer[4096];
  ssize_t numbytes = 0;
  off_t start_offset = lseek(fd, 0, SEEK_END);
  char *p = NULL;
  bool done = false;

  while (!sig_recvd && !done) {
    numbytes = recv(sock, buffer, sizeof(buffer), 0);
    if (numbytes == -1) {
      syslog(LOG_ERR, "Error in recv!: %s", strerror(errno));
      return false;
    } else if (numbytes == 0) {
      // EOF
      return false;
    }

    p = memchr(buffer, '\n', numbytes);
    if (p) {
      // truncate, keeping new line
      numbytes =  p + 1 - buffer;
      done = true;
    }

    if (write(fd, buffer, numbytes) == -1) {
      syslog(LOG_ERR, "Error in write!: %s", strerror(errno));
      ftruncate(fd, start_offset);
      return false;
    }
  }

  if (sig_recvd) {
    return false;
  }

  return true;
}

static void send_response(int sock, int fd)
{
  ssize_t numbytes = 0;
  char buffer[4096];

  if ((lseek(fd, 0, SEEK_SET)) == -1) {
    syslog(LOG_ERR, "Error in lssek!: %s", strerror(errno));
    return;
  }

  while (!sig_recvd) {
    numbytes = read(fd, buffer, sizeof(buffer));
    if (numbytes == 0) {
      return;
    } else if (numbytes == -1) {
      syslog(LOG_ERR, "Error in read!: %s", strerror(errno));
      return;
    }
    
    if (send(sock, buffer, numbytes, 0) == -1) {
      syslog(LOG_ERR, "Error in send!: %s", strerror(errno));
      return;
    }
  }
}

int main(int argc, char **argv)
{
  int i = 0;
  int sock = -1;
  bool is_daemon = false;
  struct addrinfo *ai = NULL;
  struct addrinfo hints;
  int rc = 0;
  int child = -1;
  int retval = -1;
  struct sockaddr sa;
  socklen_t salen;
  int fd = -1;
  char ipaddr[40];
  struct sigaction sigact;
  int val=1;

  memset(&hints, 0, sizeof(hints));
  openlog(NULL, 0, LOG_USER);

  for (i=1; i < argc; ++i) {
    if (!strcmp(argv[i], "-d")) {
      is_daemon = true;
    }
  }

  if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
    syslog(LOG_ERR, "Error opening file!: %s", strerror(errno));
    goto exit;
  }

  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) == -1) {
    syslog(LOG_ERR, "Error in setsockopt!: %s", strerror(errno));
    goto exit;
  }

  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = PF_INET;
  hints.ai_socktype = SOCK_STREAM;
  if ((rc = getaddrinfo(NULL, "9000", &hints, &ai)) != 0) {
    syslog(LOG_ERR, "Error in getaddrinfo!: %s", gai_strerror(rc));
    goto exit;
  }

  if (!ai) {
    syslog(LOG_ERR, "No sockaddr returned for 9000");
    goto exit;
  }

  if (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
    syslog(LOG_ERR, "Error in bind!: %s", strerror(errno));
    goto exit;
  }

  if (is_daemon) {
    pid_t childpid = fork();
    if (childpid != 0) {
      // quit parent
      _exit(0);
    }
    setsid();
    chdir("/");
    if ((freopen("/dev/null", "r", stdin) == NULL) ||
        (freopen("/dev/null", "w", stdout) == NULL) ||
        (freopen("/dev/null", "r", stderr) == NULL)) {
      syslog(LOG_ERR, "Error in redirecting i/o!: %s", strerror(errno));
      goto exit;
    }
  }

  fd = open("/var/tmp/aesdsocketdata", O_CREAT | O_TRUNC | O_RDWR, 0644);
  if (fd == -1) {
    syslog(LOG_ERR, "Error opening file!: %s", strerror(errno));
    goto exit;
  }

  if (listen(sock, 10) == -1) {
    syslog(LOG_ERR, "Error in listen!: %s", strerror(errno));
    goto exit;
  }

  memset(&sigact, 0, sizeof(sigact));
  sigact.sa_handler = sighandler;
  sigaction(SIGINT, &sigact, NULL);
  sigaction(SIGTERM, &sigact, NULL);

  while(!sig_recvd) {
    salen = sizeof(sa);
    if ((child = accept(sock, &sa, &salen)) == -1) {
      syslog(LOG_ERR, "Error in accept!: %s", strerror(errno));
      continue;
    }

    if (inet_ntop(AF_INET, &((struct sockaddr_in *)&sa)->sin_addr, ipaddr, sizeof(ipaddr)) == NULL) {
      strncpy(ipaddr, "???", sizeof(ipaddr));
    }
    syslog(LOG_DEBUG, "Accepted connection from %s", ipaddr);

    if (!read_packet(child, fd)) {
      syslog(LOG_ERR, "Error in read_packet!");
    } else {
      send_response(child, fd);
    }

    close(child);
    child = -1;
    syslog(LOG_DEBUG, "Closed connection from %s", ipaddr);
  }

  if (sig_recvd) {
    syslog(LOG_ERR, "Caught signal, exiting");
  }

  if (child != -1) {
    close(child);
    child = -1;
    syslog(LOG_DEBUG, "Closed connection from %s", ipaddr);
  }

  retval = 0;

exit:
  if (ai) {
    freeaddrinfo(ai);
  }
  if (sock != -1) {
    close(sock); 
  }
  if (child != -1) {
    close (child);
  }
  if (fd != -1) {
    close(fd);
  }
  closelog();
  return retval;
}
