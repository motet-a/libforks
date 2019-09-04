#include "./tests.h"

static int pipe_fds[2];

static void parent_main(void) {
  libforks_ServerConn conn;
  check(libforks_start(&conn) == libforks_OK);

  check(write(pipe_fds[1], "r", 1) == 1);

  sleep(999);
}

int main() {
  check(pipe(pipe_fds) == 0);

  pid_t child_pid = fork();
  check(child_pid != -1);
  if (child_pid == 0) {
    parent_main();
    abort();
  }

  char c;
  check(read(pipe_fds[0], &c, 1) == 1);
  check(c == 'r');

  check(kill(child_pid, SIGKILL) == 0);
  int wait_status;
  check(wait(&wait_status) == child_pid);
  check(WIFSIGNALED(wait_status) && WTERMSIG(wait_status) == SIGKILL);

  return 0;
}

