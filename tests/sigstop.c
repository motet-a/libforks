#include "./tests.h"


static void child_main(libforks_ServerConn conn, int socket_fd) {
  (void)conn;

  char c;
  check(read(socket_fd, &c, 1) == 1);
  check(c == 'a');
  check(write(socket_fd, "b", 1) == 1);

  sleep(999);
}

int main() {
  libforks_ServerConn conn;

  check(libforks_start(&conn) == libforks_OK);

  pid_t child_pid;
  int socket_fd;

  libforks_Result r = libforks_fork(
    conn,
    &child_pid, // pid_ptr
    &socket_fd, // socket_fd_ptr
    NULL, // exit_fd_ptr
    child_main
  );
  check(r == libforks_OK);

  check(kill(child_pid, SIGSTOP) == 0);
  check(kill(child_pid, SIGCONT) == 0);

  check(write(socket_fd, "a", 1) == 1);
  char c;
  check(read(socket_fd, &c, 1) == 1);
  check(c == 'b');

  check(libforks_stop(conn) == libforks_OK);
  return 0;
}

