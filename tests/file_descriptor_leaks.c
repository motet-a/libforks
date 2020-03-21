#include "./tests.h"

#include <sys/resource.h>

// This test creates and destroys child processes repeatedly
// and makes sure that we don’t leak any file descriptor.

#define LOOPS 19

static void child_main(libforks_ServerConn conn, int socket_fd) {
  (void)socket_fd;
  (void)conn;

  exit(0);
}


int main() {
  struct rlimit l;
  l.rlim_cur = l.rlim_max = 9;
  check(setrlimit(RLIMIT_NOFILE, &l) == 0);

  for (size_t i = 0; i < LOOPS; i++) {
    libforks_ServerConn conn;
    check(libforks_start(&conn) == libforks_OK);
    check(libforks_stop(conn) == libforks_OK);
  }

  libforks_ServerConn conn;
  check(libforks_start(&conn) == libforks_OK);

  for (size_t i = 0; i < LOOPS; i++) {
    int exit_fd;

    libforks_Result r = libforks_fork(
      conn,
      NULL, // pid_ptr
      NULL, // socket_fd_ptr
      &exit_fd, // exit_fd_ptr
      child_main
    );
    check(r == libforks_OK);

    libforks_ExitEvent event;
    check(read(exit_fd, &event, sizeof event) == sizeof event);

    check(close(exit_fd) == 0);
  }

  check(libforks_stop(conn) == libforks_OK);

  return 0;
}

