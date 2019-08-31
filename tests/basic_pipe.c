#include "./tests.h"

static int pipe_fds[2];
static int main_process_pid;

static void child_main(libforks_ServerConn conn, int socket_fd) {
  check(libforks_free_conn(conn) == libforks_OK);
  check(close(pipe_fds[0]) == 0);
  check(socket_fd == -1);
  check(getpid() != main_process_pid);
  check(write(pipe_fds[1], "a", 1) == 1);
}

int main() {
  libforks_ServerConn conn;

  main_process_pid = getpid();

  check(pipe(pipe_fds) == 0);

  check(libforks_start(&conn) == libforks_OK);

  check(close(pipe_fds[1]) == 0);

  check(libforks_fork(
    conn,
    NULL, // pid_ptr
    NULL, // socket_fd_ptr
    NULL, // exit_fd_ptr
    child_main
  ) == libforks_OK);

  check(libforks_stop(conn) == libforks_OK);

  // Make sure that we can read one and only one char written by the
  // child process
  char buffer[16];
  check(read(pipe_fds[0], buffer, sizeof buffer) == 1);
  check(buffer[0] == 'a');

  return 0;
}

