#include "./tests.h"

#include <sys/resource.h>

static void child_main(libforks_ServerConn conn, int socket_fd) {
  (void)socket_fd;
  (void)conn;

  sleep(99);
}


int main() {
  struct rlimit l;
  l.rlim_cur = l.rlim_max = 10;
  check(setrlimit(RLIMIT_NOFILE, &l) == 0);

  libforks_ServerConn conn;
  check(libforks_start(&conn) == libforks_OK);

  while (true) {
    libforks_Result r = libforks_fork(
      conn,
      NULL, // pid_ptr
      NULL, // socket_fd_ptr
      NULL, // exit_fd_ptr
      child_main
    );
    if (r != libforks_OK) {
      check(r == libforks_SOCKET_CREATION_ERROR);
      check(errno == EMFILE);
      break;
    }
    check(r == libforks_OK);
  }

  check(libforks_stop(conn) == libforks_OK);

  return 0;
}

