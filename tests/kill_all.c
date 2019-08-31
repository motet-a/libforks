#include "./tests.h"

static int child_socket_fd;

static void child_handle_sigusr1(int n) {
  (void)n;
  check(write(child_socket_fd, "s", 1) == 1);
}

static void child_main(libforks_ServerConn conn, int socket_fd) {
  (void)conn;
  child_socket_fd = socket_fd;
  check(signal(SIGUSR1, child_handle_sigusr1) != SIG_ERR);
  check(write(socket_fd, "r", 1) == 1); // tell the parent process that we are ready
  sleep(999);
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

  // is the child ready to receive the signal?
  char c;
  check(read(socket_fd, &c, 1) == 1);
  check(c == 'r');

  check(libforks_kill_all(conn, SIGUSR1) == libforks_OK);

  check(read(socket_fd, &c, 1) == 1);
  check(c == 's');

  check(libforks_stop(conn) == libforks_OK);
  return 0;
}

