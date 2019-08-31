#include "./tests.h"
#include <sys/types.h>
#include <sys/dir.h>

// Test runner program.

int main() {
  DIR *dir = opendir(".");
  check(dir);

  int exit_status = 0;

  const struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strchr(entry->d_name, '.')) {
      continue;
    }
    if (strcmp(entry->d_name, "main") == 0) {
      continue;
    }

    printf("testing %s...", entry->d_name);
    char exec_path[strlen(entry->d_name) + 3];
    check(snprintf(exec_path, sizeof exec_path, "./%s", entry->d_name) != -1);

    char *argv[] = {exec_path, NULL};
    char *envp[] = {
      "MALLOC_OPTIONS=S", // security options for OpenBSD
      NULL
    };

    pid_t child_pid = fork();
    check(child_pid != -1);

    if (child_pid == 0) {
      check(setpgid(getpid(), getpid()) == 0);
      check(execve(exec_path, argv, envp));
      abort();
    }

    char failure[99];
    failure[0] = '\0';

    int wait_status;
    check(waitpid(child_pid, &wait_status, 0) > 0);
    if (WIFEXITED(wait_status)) {
      if (WEXITSTATUS(wait_status) != 0) {
        snprintf(failure, sizeof failure, "exited with status %d", WEXITSTATUS(wait_status));
      }
    } else if (WIFSIGNALED(child_pid)) {
      snprintf(failure, sizeof failure, "received signal");
    } else {
      abort();
    }

    // wait for the whole process group
    if (waitpid(-child_pid, &wait_status, WNOHANG) > 0) {
      snprintf(failure, sizeof failure, "children are still running");
      killpg(child_pid, SIGKILL);
    }

    if (*failure) {
      exit_status = 1;
      printf(" error: %s\n", failure);
    } else {
      printf(" ok\n");
    }
  }

  check(closedir(dir) == 0);

  return exit_status;
}

