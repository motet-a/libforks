#include <libforks.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>

// This is a (terribly overengineered) multithreaded fizz buzz program
// showing how to use libforks with threads

#define MAX 99

static int threads_output_fd;
static libforks_ServerConn conn;

static void sort_main(libforks_ServerConn conn, int socket_fd) {
  // not strictly required but recommended
  assert(libforks_free_conn(conn) == libforks_OK);

  assert(dup2(socket_fd, STDIN_FILENO) != -1);

  execlp("sort", "sort", "-g", NULL);
  perror("execlp");
  abort();
}

static void echo_upper_main(libforks_ServerConn conn, int socket_fd) {
  // not strictly required but recommended
  assert(libforks_free_conn(conn) == libforks_OK);

  int out, ready_fd;
  char c;
  assert(libforks_read_socket_fds(socket_fd, &c, 1, &out, 1) == 0);
  assert(c == 'a');
  assert(libforks_read_socket_fds(socket_fd, &c, 1, &ready_fd, 1) == 0);
  assert(c == 'b');

  assert(dup2(socket_fd, STDIN_FILENO) != -1);
  assert(dup2(out, STDOUT_FILENO) != -1);
  close(socket_fd);
  close(out);

  // Inform the parent process that we’re ready to receive input
  assert(write(ready_fd, "c", 1) == 1);
  close(ready_fd);

  execlp("tr", "tr", "[:lower:]", "[:upper:]", NULL); // uppercase!
  perror("execlp");
  abort();
}

static void echo_upper(const char *text) {
  int socket_fd;
  int exit_fd;

  assert(libforks_fork(
    conn,
    NULL, // pid_ptr
    &socket_fd, // socket_fd_ptr
    &exit_fd, // exit_fd_ptr
    echo_upper_main
  ) == libforks_OK);

  int ready_pipe[2];
  assert(pipe(ready_pipe) == 0);

  assert(libforks_write_socket_fds(socket_fd, "a", 1, &threads_output_fd, 1) == 0);
  assert(libforks_write_socket_fds(socket_fd, "b", 1, &ready_pipe[1], 1) == 0);

  // wait until the child process finishes to setup its file descriptors
  char c;
  assert(read(ready_pipe[0], &c, 1) == 1);
  close(ready_pipe[0]);
  close(ready_pipe[1]);

  assert(write(socket_fd, text, strlen(text)) == (ssize_t)strlen(text));

  // `shutdown` is necessary here to send EOF
  int r = shutdown(socket_fd, SHUT_WR);
  assert(r == 0);
  assert(close(socket_fd) == 0);

  libforks_ExitEvent ee;
  assert(read(exit_fd, &ee, sizeof ee) == sizeof ee);
  close(exit_fd);
}

static void *fizzer_main() {
  char buf[99];
  for (int i = 1; i < MAX; i++) {
    if (i % 3 == 0) {
      snprintf(buf, sizeof buf, "%d fizz\n", i);
      echo_upper(buf);
    }
  }

  return NULL;
}

static void *buzzer_main() {
  char buf[99];
  for (int i = 1; i < MAX; i++) {
    if (i % 5 == 0) {
      snprintf(buf, sizeof buf, "%d buzz\n", i);
      echo_upper(buf);
    }
  }

  return NULL;
}

int main() {
  assert(libforks_start(&conn) == libforks_OK);

  int exit_fd;

  assert(libforks_fork(
    conn,
    NULL, // pid_ptr
    &threads_output_fd, // socket_fd_ptr
    &exit_fd, // exit_fd_ptr
    sort_main
  ) == libforks_OK);

  pthread_t fizzer, buzzer;
  assert(pthread_create(&fizzer, NULL, fizzer_main, NULL) == 0);
  assert(pthread_create(&buzzer, NULL, buzzer_main, NULL) == 0);

  void *res;
  assert(pthread_join(fizzer, &res) == 0);
  assert(pthread_join(buzzer, &res) == 0);

  // `shutdown` is necessary here to send EOF to sort’s stdin
  assert(shutdown(threads_output_fd, SHUT_WR) == 0);
  assert(close(threads_output_fd) == 0);

  // `sort` exits here, the fork server receives SIGCHLD and writes
  // the exit event to `exit_fd`. The event stays in the `exit_fd`
  // buffer until we read it so there’s no race condition.

  libforks_ExitEvent ee;
  assert(read(exit_fd, &ee, sizeof ee) == sizeof ee);
  close(exit_fd);

  assert(libforks_stop(conn) == libforks_OK);
  return 0;
}

