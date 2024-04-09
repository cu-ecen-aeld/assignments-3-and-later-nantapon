#include <syslog.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

int main(int argc, char **argv)
{
  openlog(NULL, 0, LOG_USER);

  if (argc != 3) {
    syslog(LOG_ERR, "Need 2 arguments!");
    return 1;
  }

  int fd = open(argv[1], O_CREAT | O_TRUNC | O_APPEND | O_WRONLY, 0644);
  if (fd == -1) {
    syslog(LOG_ERR, "Error opening file!: %s", strerror(errno));
    return 1;
  }

  ssize_t n = write(fd, argv[2], strlen(argv[2]));
  if (n == -1) {
    syslog(LOG_ERR, "write error!: %s", strerror(errno));
    return 1;
  }

  close(fd);
  syslog(LOG_DEBUG, "Writing %s to %s", argv[2], argv[1]);
  closelog();

  return 0;
}