#include <libforks.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

extern char **environ;

static void child_main(libforks_ServerConn conn, int socket_fd) {
  assert(socket_fd == -1);

  // not strictly required but recommended
  assert(libforks_free_conn(conn) == libforks_OK);

  char * const argv[] = {
    "echo",
    "hello, world!",
    NULL
  };
  execve("/bin/echo", argv, environ);
  perror("execve");
  abort();
}

int main() {
  libforks_ServerConn conn;
  assert(libforks_start(&conn) == libforks_OK);

  int exit_fd;

  assert(libforks_fork(
    conn,
    NULL, // pid_ptr
    NULL, // socket_fd_ptr
    &exit_fd, // exit_fd_ptr
    child_main
  ) == libforks_OK);

  libforks_ExitEvent ee;
  assert(read(exit_fd, &ee, sizeof ee) == sizeof ee);

  assert(libforks_stop(conn) == libforks_OK);
  return 0;
}

