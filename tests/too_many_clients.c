#include "./tests.h"


static void child_main(libforks_ServerConn conn, int socket_fd) {
  (void)socket_fd;
  (void)conn;

  sleep(99);
}

int main() {
  libforks_ServerConn conn;

  check(libforks_start(&conn) == libforks_OK);

  for (size_t i = 0; i < 19; i++) {
    libforks_Result r = libforks_fork(
      conn,
      NULL, // pid_ptr
      NULL, // socket_fd_ptr
      NULL, // exit_fd_ptr
      child_main
    );
    check(r == libforks_OK);
  }

  libforks_Result r = libforks_fork(
    conn,
    NULL, // pid_ptr
    NULL, // socket_fd_ptr
    NULL, // exit_fd_ptr
    child_main
  );
  check(r == libforks_TOO_MANY_CLIENTS_ERROR);

  check(libforks_stop(conn) == libforks_OK);

  return 0;
}

