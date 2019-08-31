#define _DEFAULT_SOURCE

#include "../libforks.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>

#define check(e) ((void)(e ? (void)0 : check_failure(#e, __FILE__, __LINE__)))

static void check_failure(const char *assertion, const char *file, int line) {
  fprintf(stderr, "check \"%s\" failed in %s:%d\n", assertion, file, line);
  abort();
}

