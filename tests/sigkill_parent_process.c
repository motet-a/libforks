#include "./tests.h"

static int pipe_fds[2];

static void parent_main(void) {
  libforks_ServerConn conn;
  check(libforks_start(&conn) == libforks_OK);

  pid_t serv_pid = libforks_get_server_pid(conn);
  check(write(pipe_fds[1], &serv_pid, sizeof serv_pid) == sizeof serv_pid);

  sleep(999);
}

int main() {
  check(pipe(pipe_fds) == 0);

  pid_t child_pid = fork();
  check(child_pid != -1);
  if (child_pid == 0) {
    check(close(pipe_fds[0]) == 0);
    parent_main();
    abort();
  }

  check(close(pipe_fds[1]) == 0);

  pid_t serv_pid;
  check(read(pipe_fds[0], &serv_pid, sizeof serv_pid) == sizeof serv_pid);

  check(kill(child_pid, SIGKILL) == 0);

  int wait_status;
  check(wait(&wait_status) == child_pid);
  check(WIFSIGNALED(wait_status));
  check(WTERMSIG(wait_status) == SIGKILL);

  while (true) {
    if (kill(serv_pid, 0) == -1) {
      check(errno == ESRCH);
      break;
    }
  }

  return 0;
}

