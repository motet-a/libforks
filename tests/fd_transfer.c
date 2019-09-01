#include "./tests.h"

int main() {
  int sockets[2];
  check(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);

  pid_t child_pid = fork();
  if (child_pid == 0) {
    close(sockets[1]);
    char c = '\0';

    check(libforks_read_socket_fds(sockets[0], &c, 1, NULL, 0) == 0);
    check(c == 'b');

    int fds[3] = {-1, -1, -1};
    check(
      libforks_read_socket_fds(
          sockets[0],
          &c, 1,
          fds, 2) == 0
    );
    check(c == 'a');
    check(fds[0] > 2);
    check(fds[1] == -1);
    check(fds[2] == -1);

    char buffer[99];
    check(read(fds[0], buffer, sizeof buffer) > 0);
    check(strcmp(buffer, "hello") == 0);

    check(libforks_read_socket_fds(sockets[0], &c, 1, NULL, 0) == 0);
    check(c == 'r');

    exit(0);
  }

  close(sockets[0]);

  int pipe_fds[2];
  check(pipe(pipe_fds) == 0);

  check(libforks_write_socket_fds(sockets[1], "b", 1, NULL, 0) == 0);
  check(libforks_write_socket_fds(sockets[1], "ar", 3, &pipe_fds[0], 1) == 0);

  check(close(pipe_fds[0]) == 0);

  check(write(pipe_fds[1], "hello", 6) == 6);

  int wait_status;
  check(wait(&wait_status) != -1);
}

