#include <libforks.h>
#include <assert.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>

// This example shows how to communicate with a child process
// using the socket creation facility. The main process sends
// stdin to the child process, the child process transforms
// every character to its uppercase equivalent and sends
// it back to the main process that prints it on stdout.

static void child_main(libforks_ServerConn conn, int socket_fd) {
  (void)conn;

  while (true) {
    char c;
    assert(read(socket_fd, &c, 1) == 1);
    c = toupper(c);
    assert(write(socket_fd, &c, 1) == 1);
  }
}

int main() {
  libforks_ServerConn conn;
  assert(libforks_start(&conn) == libforks_OK);

  int socket_fd;

  assert(libforks_fork(
    conn,
    NULL, // pid_ptr
    &socket_fd, // socket_fd_ptr
    NULL, // exit_fd_ptr
    child_main
  ) == libforks_OK);

  puts("Type text and press enter");
  puts("Exit with Ctrl+D");

  while (true) {
    char c;
    int read_res = read(STDIN_FILENO, &c, 1);
    if (read_res == 0) { // EOF
      assert(libforks_stop(conn, true) == libforks_OK);
      break;
    }
    assert(read_res == 1);

    assert(write(socket_fd, &c, 1) == 1);
    assert(read(socket_fd, &c, 1) == 1);
    assert(write(STDOUT_FILENO, &c, 1) == 1);
  }

  return 0;
}

