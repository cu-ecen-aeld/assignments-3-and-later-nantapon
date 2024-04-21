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
#include <pthread.h>
#include "queue.h"
#include <stdatomic.h>
#include <stdlib.h>

#ifndef USE_AESD_CHAR_DEVICE
#define USE_AESD_CHAR_DEVICE 1
#endif

struct thread_data {
  int sock;
  struct sockaddr sa;
  socklen_t salen;
  pthread_t thread;
  volatile bool thread_exited;
  SLIST_ENTRY(thread_data) next;
};

static int fd = -1;
static bool sig_recvd = false;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile uint32_t thread_exit_counter = 0;
static SLIST_HEAD(thread_data_head, thread_data) list = SLIST_HEAD_INITIALIZER(thread_data_head);
static pthread_t main_thread;
static sigset_t signal_mask;


static void sighandler(int x)
{

}

static bool read_packet(int sock, int fd)
{
  bool retval = false;
  char buffer[4096];
  ssize_t numbytes = 0;
#if !USE_AESD_CHAR_DEVICE
  off_t start_offset = lseek(fd, 0, SEEK_END);
#endif
  char *p = NULL;
  bool done = false;

#if USE_AESD_CHAR_DEVICE
  // reopen the device so that we can start from the begining.
  fd = open("/dev/aesdchar", O_CREAT | O_TRUNC | O_RDWR, 0644);
  if (fd == -1) {
    syslog(LOG_ERR, "Error opening file!: %s", strerror(errno));
    return false;
  }
#endif

  while (!sig_recvd && !done) {
    numbytes = recv(sock, buffer, sizeof(buffer), 0);
    if (numbytes == -1) {
      syslog(LOG_ERR, "Error in recv!: %s", strerror(errno));
      goto exit;
    } else if (numbytes == 0) {
      // EOF
      goto exit;
    }

    p = memchr(buffer, '\n', numbytes);
    if (p) {
      // truncate, keeping new line
      numbytes =  p + 1 - buffer;
      done = true;
    }

    if (write(fd, buffer, numbytes) == -1) {
      syslog(LOG_ERR, "Error in write!: %s", strerror(errno));
#if !USE_AESD_CHAR_DEVICE
      ftruncate(fd, start_offset);
#endif
      goto exit;
    }
  }

  if (sig_recvd) {
    goto exit;
  }

  retval = true;

exit:
#if USE_AESD_CHAR_DEVICE
  close(fd);
#endif
  return retval;

}

static void send_response(int sock, int fd)
{
  ssize_t numbytes = 0;
  char buffer[4096];

#if !USE_AESD_CHAR_DEVICE
  if ((lseek(fd, 0, SEEK_SET)) == -1) {
    syslog(LOG_ERR, "Error in lseek!: %s", strerror(errno));
    return;
  }
#else
  // reopen the device so that we can start from the begining.
  fd = open("/dev/aesdchar", O_CREAT | O_TRUNC | O_RDWR, 0644);
  if (fd == -1) {
    syslog(LOG_ERR, "Error opening file!: %s", strerror(errno));
    return;
  }
#endif

  while (!sig_recvd) {
    numbytes = read(fd, buffer, sizeof(buffer));
    if (numbytes == 0) {
      break;
    } else if (numbytes == -1) {
      syslog(LOG_ERR, "Error in read!: %s", strerror(errno));
      break;
    }
    
    if (send(sock, buffer, numbytes, 0) == -1) {
      syslog(LOG_ERR, "Error in send!: %s", strerror(errno));
      break;
    }
  }
#if USE_AESD_CHAR_DEVICE
  close(fd);
#endif
}

static void *thread_start(void *arg)
{
  struct thread_data *td = arg;
  char ipaddr[40];

  pthread_mutex_lock(&mutex);

  if (inet_ntop(AF_INET, &((struct sockaddr_in *)&td->sa)->sin_addr, ipaddr, sizeof(ipaddr)) == NULL) {
    strncpy(ipaddr, "???", sizeof(ipaddr));
  }
  syslog(LOG_DEBUG, "Accepted connection from %s", ipaddr);

  if (!read_packet(td->sock, fd)) {
    syslog(LOG_ERR, "Error in read_packet!");
  } else {
    send_response(td->sock, fd);
  }

  close(td->sock);
  td->sock = -1;
  syslog(LOG_DEBUG, "Closed connection from %s", ipaddr);
  __atomic_store_n(&td->thread_exited, true, __ATOMIC_RELEASE);
  __atomic_add_fetch(&thread_exit_counter, 1, __ATOMIC_RELEASE);

  pthread_mutex_unlock(&mutex);
  return NULL;
}

static void *timer_thread_start(void *arg)
{
  char buffer[100];
  time_t t;
  struct tm tm;
  size_t n;

  while (!sig_recvd) {
    if (usleep(10 * 1000000) == -1) {
      continue;
    }

    pthread_mutex_lock(&mutex);
    do {
      t = time(NULL);
      if (localtime_r(&t, &tm) == NULL) {
        syslog(LOG_ERR, "localtime_r returns error: %s", strerror(errno));
        break;
      }

      if ((n = strftime(buffer, sizeof(buffer), "timestamp:%a, %d %b %Y %T %z\n", &tm)) == 0) {
        syslog(LOG_ERR, "strftime returns error");
        break;
      }

      if (write(fd, buffer, n) == -1) {
        syslog(LOG_ERR, "Error in write!: %s", strerror(errno));
        break;
      }
    } while(0);

    pthread_mutex_unlock(&mutex);
  }
  return NULL;
}

static void *signal_thread_start(void *arg)
{
  int rc;
  int sig_caught;

  while (true) { 
    if ((rc = sigwait(&signal_mask, &sig_caught)) != 0) {
      syslog(LOG_ERR, "pthread_join returns error: %s", strerror(rc)); 
    }
    switch (sig_caught)
    {
    case SIGINT:   
    case SIGTERM:
        sig_recvd = true;
        pthread_kill(main_thread, SIGUSR1);
        return NULL;

    default:      
      syslog(LOG_ERR, "Unexpected signal: %d", sig_caught); 
    }
  }
}

static bool start_server_thread(int sock, const struct sockaddr *sa, socklen_t salen)
{
  struct thread_data *td = calloc(1, sizeof(struct thread_data));
  int rc = 0;
  if (!td) {
      return false;
  }
  td->sock = sock;
  td->sa = *sa;
  td->salen = salen;

  if ((rc = pthread_create(&td->thread, NULL, thread_start, td)) != 0) {
      free(td);
      syslog(LOG_ERR, "pthread_create returns error: %s", strerror(rc));
      return false;
  }

  return true;
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
  int val=1;
  uint32_t exit_counter = 0;
  struct thread_data *td = NULL;
  struct thread_data *td_next = NULL;
  pthread_t timer_thread;
  pthread_t signal_thread;
  struct sigaction sigact;
#if USE_AESD_CHAR_DEVICE
  bool enable_timer = false;
#else
  bool enable_timer = true;
#endif

  main_thread = pthread_self();
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

#if !USE_AESD_CHAR_DEVICE
  fd = open("/var/tmp/aesdsocketdata", O_CREAT | O_TRUNC | O_RDWR, 0644);
  if (fd == -1) {
    syslog(LOG_ERR, "Error opening file!: %s", strerror(errno));
    goto exit;
  }
#endif

  if (listen(sock, 10) == -1) {
    syslog(LOG_ERR, "Error in listen!: %s", strerror(errno));
    goto exit;
  }

  memset(&sigact, 0, sizeof(sigact));
  sigact.sa_handler = sighandler;
  sigaction(SIGUSR1, &sigact, NULL);

  sigemptyset (&signal_mask);
  sigaddset (&signal_mask, SIGINT);
  sigaddset (&signal_mask, SIGTERM);
  if ((rc = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL)) == -1) {
    syslog(LOG_ERR, "pthread_sigmask returns error: %s", strerror(rc));
    goto exit;
  }

  if ((rc = pthread_create(&signal_thread, NULL, signal_thread_start, NULL)) != 0) {
    syslog(LOG_ERR, "pthread_create returns error: %s", strerror(rc));
    goto exit;
  }

  if (enable_timer) {
    if ((rc = pthread_create(&timer_thread, NULL, timer_thread_start, NULL)) != 0) {
      syslog(LOG_ERR, "pthread_create returns error: %s", strerror(rc));
      goto exit;
    }
  }

  while(!sig_recvd) {
    uint32_t e = 0;
    int child = -1;

    salen = sizeof(sa);
    if ((child = accept(sock, &sa, &salen)) == -1) {
      syslog(LOG_ERR, "Error in accept!: %s", strerror(errno));
      continue;
    }

    start_server_thread(child, &sa, salen);

    if (exit_counter < (e = __atomic_load_n(&thread_exit_counter, __ATOMIC_ACQUIRE))) {
      exit_counter = e;
      SLIST_FOREACH_SAFE(td, &list, next, td_next) {
        if (__atomic_load_n(&td->thread_exited, __ATOMIC_ACQUIRE)) {
          SLIST_REMOVE(&list, td, thread_data, next);
          if ((rc = pthread_join(td->thread, NULL)) != 0) {
            syslog(LOG_ERR, "pthread_join returns error: %s", strerror(rc));
          }
          free(td);
        }
      }
    }
  }

  if (sig_recvd) {
    syslog(LOG_ERR, "Caught signal, exiting");
  }

  if (enable_timer) {
    pthread_kill(timer_thread, SIGUSR1);
  }

  SLIST_FOREACH_SAFE(td, &list, next, td_next) {
    if ((rc = pthread_join(td->thread, NULL)) != 0) {
      syslog(LOG_ERR, "pthread_join returns error: %s", strerror(rc));
    }
    free(td);
  }

  if (enable_timer) {
    if ((rc = pthread_join(timer_thread, NULL)) != 0) {
        syslog(LOG_ERR, "pthread_join returns error: %s", strerror(rc));
    }
  }

  if ((rc = pthread_join(signal_thread, NULL)) != 0) {
      syslog(LOG_ERR, "pthread_join returns error: %s", strerror(rc));
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
#if !USE_AESD_CHAR_DEVICE
  unlink("/var/tmp/aesdsocketdata");
#endif
  closelog();
  return retval;
}
