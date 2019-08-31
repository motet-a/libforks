#include "./tests.h"


static void child_main(libforks_ServerConn conn, int socket_fd) {
  (void)socket_fd;
  (void)conn;

  exit(23);
}

int main() {
  libforks_ServerConn conn;

  check(libforks_start(&conn) == libforks_OK);

  int exit_fd;
  pid_t child_pid;

  libforks_Result r = libforks_fork(
    conn,
    &child_pid, // pid_ptr
    NULL, // socket_fd_ptr
    &exit_fd, // exit_fd_ptr
    child_main
  );
  check(r == libforks_OK);

  libforks_ExitEvent event;
  check(read(exit_fd, &event, sizeof event) == sizeof event);
  check(event.pid == child_pid);
  check(WIFEXITED(event.wait_status));
  check(WEXITSTATUS(event.wait_status) == 23);

  check(libforks_stop(conn) == libforks_OK);

  return 0;
}

