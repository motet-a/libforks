#include <libforks.h>
#include <assert.h>
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

  int out;
  char c;
  assert(libforks_read_socket_fds(socket_fd, &c, 1, &out, 1) == 0);
  assert(c == 'r');

  assert(dup2(socket_fd, STDIN_FILENO) != -1);
  assert(dup2(out, STDOUT_FILENO) != -1);

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

  assert(libforks_write_socket_fds(socket_fd, "r", 1, &threads_output_fd, 1) == 0);

  assert(write(socket_fd, text, strlen(text)) == (ssize_t)strlen(text));
  assert(shutdown(socket_fd, SHUT_RDWR) == 0);
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

  // `shutdown` is necessary here
  assert(shutdown(threads_output_fd, SHUT_RDWR) == 0);
  assert(close(threads_output_fd) == 0);

  libforks_ExitEvent ee;
  assert(read(exit_fd, &ee, sizeof ee) == sizeof ee);
  close(exit_fd);

  assert(libforks_stop(conn) == libforks_OK);
  return 0;
}

