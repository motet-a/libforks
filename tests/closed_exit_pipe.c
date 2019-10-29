#include "./tests.h"

static void child_main(libforks_ServerConn conn, int socket_fd) {
  (void)conn;
  char c;
  check(read(socket_fd, &c, 1) == 1);
  check(c == 'o');
}

static void serv_wait(void) {
  int wait_status;
  wait(&wait_status);
}

int main() {
  libforks_ServerConn conn;

  check(libforks_start(&conn) == libforks_OK);

  int exit_fd;
  pid_t child_pid;
  int socket_fd;

  libforks_Result r = libforks_fork(
    conn,
    &child_pid, // pid_ptr
    &socket_fd, // socket_fd_ptr
    &exit_fd, // exit_fd_ptr
    child_main
  );
  check(r == libforks_OK);

  close(exit_fd);
  write(socket_fd, "o", 1);
  check(write(socket_fd, "o", 1) == 1);

  // child exits now, but since exit_fd is closed we have to do this
  // dirty hack
  check(libforks_eval(conn, serv_wait) == libforks_OK);

  check(libforks_stop(conn) == libforks_OK);

  return 0;
}

