#include "./tests.h"

int pipe_fds[2];

static void child_main(libforks_ServerConn conn, int socket_fd) {
  (void)socket_fd;

  check(libforks_free_conn(conn) == libforks_OK);
  check(close(pipe_fds[0]) == 0);
  pid_t pid = getpid();
  check(write(pipe_fds[1], (void*)&pid, sizeof pid) == sizeof pid);
}

int main() {
  libforks_ServerConn conn;

  check(pipe(pipe_fds) == 0);

  check(libforks_start(&conn) == libforks_OK);

  pid_t child_pid;

  check(libforks_fork(
    conn,
    &child_pid, // pid_ptr
    NULL, // socket_fd_ptr
    NULL, // exit_fd_ptr
    child_main
  ) == libforks_OK);

  pid_t received_child_pid;
  check(
    read(
      pipe_fds[0],
      &received_child_pid, sizeof received_child_pid
    ) == sizeof received_child_pid
  ); // blocks until the child writes
  check(child_pid == received_child_pid);

  check(libforks_stop(conn, true) == libforks_OK);

  check(child_pid == received_child_pid);

  return 0;
}

