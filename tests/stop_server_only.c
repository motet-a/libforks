#include "./tests.h"

static void child_main(libforks_ServerConn conn, int socket_fd) {
  (void)conn;

  char c;
  check(read(socket_fd, &c, 1) == 1);
  check(c == 'a');
  check(write(socket_fd, "b", 1) == 1);
}

int main() {
  libforks_ServerConn conn;
  check(libforks_start(&conn) == libforks_OK);

  int socket_fd;

  check(libforks_fork(
    conn,
    NULL, // pid_ptr
    &socket_fd, // socket_fd_ptr
    NULL, // exit_fd_ptr
    child_main
  ) == libforks_OK);

  check(libforks_stop_server_only(conn) == libforks_OK);

  // The child process is now daemonized and still running.
  // Try to communicate with it.

  check(write(socket_fd, "a", 1) == 1);
  char c;
  check(read(socket_fd, &c, 1) == 1);
  check(c == 'b');
  return 0;
}

