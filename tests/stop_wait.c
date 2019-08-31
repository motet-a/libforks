#include "./tests.h"

#include <time.h>
#include <errno.h>

int pipe_fds[2];

static void child_main(libforks_ServerConn conn, int socket_fd) {
  (void)conn;
  (void)socket_fd;

  check(signal(SIGTERM, SIG_IGN) != SIG_ERR);

  // sleep 10ms
  struct timespec ts = {
    .tv_sec = 0,
    .tv_nsec = 10 * 1000 * 1000,
  };
  check(nanosleep(&ts, NULL) == 0);

  check(write(pipe_fds[1], "a", 1) == 1);
}

int main() {
  libforks_ServerConn conn;

  check(pipe(pipe_fds) == 0);
  check(fcntl(pipe_fds[0], F_SETFL, O_NONBLOCK) != -1);

  check(libforks_start(&conn) == libforks_OK);

  check(close(pipe_fds[1]) == 0);

  check(libforks_fork(
    conn,
    NULL, // pid_ptr
    NULL, // socket_fd_ptr
    NULL, // exit_fd_ptr
    child_main
  ) == libforks_OK);

  char c;
  check(read(pipe_fds[0], &c, 1) == -1);
  check(errno == EAGAIN);

  check(libforks_stop(conn) == libforks_OK); // SIGTERM sent but ignored by the child

  check(read(pipe_fds[0], &c, 1) == 1);
  check(c == 'a');
  return 0;
}

