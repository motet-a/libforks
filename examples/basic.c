#include <libforks.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>

// This example program starts a child process and exits immediately.
// The child process keeps running during one second.

static void child_main(libforks_ServerConn conn, int socket_fd) {
  (void)conn;

  assert(socket_fd == -1);
  puts("child process started");
  sleep(1);
  puts("child process exited");
}

int main() {
  libforks_ServerConn conn;

  assert(libforks_start(&conn) == libforks_OK);

  assert(libforks_fork(
    conn,
    NULL, // pid_ptr
    NULL, // socket_fd_ptr
    NULL, // exit_fd_ptr
    child_main
  ) == libforks_OK);

  assert(libforks_stop(conn, true) == libforks_OK);

  puts("main process exited");

  return 0;
}

