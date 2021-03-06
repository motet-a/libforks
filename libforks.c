// Copyright Ericsson AB 1996-2018. All Rights Reserved.
// Copyright 2019-2020 Antoine Motet
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define _DEFAULT_SOURCE

#include "libforks.h"

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

// Helpful links:
//  - Python documentation and CPython source code about forkservers: https://docs.python.org/3/library/multiprocessing.html
//  - erts/emulator/sys/unix/erl_child_setup.c in the Erlang/OTP source code: https://github.com/erlang/otp/blob/b5ab81f3617bb9cb936beaacadae967d3c9ce541/erts/emulator/sys/unix/erl_child_setup.c
//
// Symbols that are specific to the server have a name prefixed by serv_.


// XXX `serv_DEBUG` is guaranteed to be async-signal-safe in two cases:
//   - if you’re on a system where dprintf is async-signal-safe (it’s
//   guaranteed on OpenBSD but not on Linux, even if dprintf is likely
//   async-signal safe on any Unix system out there);
//   - or, more commonly, if debugging is disabled (that should be almost
//   always the case).
//
// Thus, this program assumes that `serv_DEBUG` is always async-signal-safe
// even if POSIX disagrees.
#ifdef LIBFORKS_DEBUG
#  define serv_DEBUG(...) (dprintf(STDERR_FILENO, "libforks server: " __VA_ARGS__))
#else
#  define serv_DEBUG(...)
#endif

#ifndef serv_MAX_CLIENTS
#  define serv_MAX_CLIENTS 1023
#endif

#define CMSG_BUFFER_SIZE (sizeof(int) * 32)

// To make pipe(2) easier to understand
#define READ_END 0
#define WRITE_END 1


// There’s a protocol between the fork server and its clients
typedef enum {
  ClientMessageType_FORK_REQUEST,
  ClientMessageType_STOP_SERVER_ONLY_REQUEST,
  ClientMessageType_STOP_ALL_REQUEST,
  ClientMessageType_KILL_ALL_REQUEST,
  ClientMessageType_EVAL_REQUEST,
} ClientMessageType;

typedef struct {
  union {
    struct {
      bool create_user_socket;
      bool create_exit_pipe;
      void (*entrypoint)(libforks_ServerConn conn, int socket_fd);
    } fork_request;

    struct {
      int signal;
    } kill_all_request;

    struct {
      void (*function)(void);
    } eval_request;
  } u;
  ClientMessageType type;
} ClientMessage;

typedef enum {
  ServerMessageType_FORK_SUCCESS,
  ServerMessageType_FORK_FAILURE,
  ServerMessageType_KILL_SUCCESS,
  ServerMessageType_EVAL_SUCCESS,
} ServerMessageType;

typedef struct {
  union {
    struct {
      pid_t pid;
      // user socket fd and exit fd are transmitted in headers along
      // this message
    } fork_success;

    struct {
      libforks_Result error_code;
      int saved_errno;
    } fork_failure;
  } u;
  ServerMessageType type;
} ServerMessage;


// The private struct pointed to by `libforks_ServerConn` pointers.
// There is one different instance of this struct in each client process.
typedef struct {
  int server_pid;
  int socket; // used to communicate with the server (bidirectional)
} ServerConn;

struct serv_Client;
typedef struct serv_Client serv_Client;

// A client connected to the fork server. Keep in mind that each child process
// is also a client.
struct serv_Client {
  pid_t pid;

  // `true` if this client is the one that called `libforks_start`
  bool main;

  // used to communicate with the server (bidirectional)
  //
  // -1 means that the client is a “zombie”, i.e. its socket is
  // closed and it is permanently disconnected from the server
  // but the parent of this client has not been notified yet so
  // we have to keep it in the linked list for a while.
  int socket;

  // -1 if no exit file descriptor
  int exit_fd;

  // linked list
  serv_Client *next;
};



// Pipe used inside the server process by the SIGCHLD signal
// handler to communicate exit events to the main server loop
// (because that’s async-signal safe).
//
// Unused in client processes.
static int serv_exit_pipe[2];


// It is mostly safe to ignore errors returned by `close`
// https://lwn.net/Articles/576478/
#ifndef NDEBUG
static int checked_close(int fd) {
  if (close(fd) != 0) {
    perror("libforks: close");
    abort();
  }
  return 0;
}
#define close(fd) checked_close(fd)
#endif // NDEBUG


// Reads exactly `length` bytes. Async-signal-safe.
__attribute__((warn_unused_result))
static int read_exact(int fd, void *data, size_t length) {
  ssize_t res = read(fd, data, length);
  if (res == -1) {
    return -1;
  }
  if (res != (ssize_t)length) {
    errno = EMSGSIZE;
    return -1;
  }
  return 0;
}

// Writes exactly `length` bytes. Async-signal-safe.
__attribute__((warn_unused_result))
static int write_exact(int fd, const void *data, size_t length) {
  ssize_t res = write(fd, data, length);
  if (res == -1) {
    return -1;
  }
  if (res != (ssize_t)length) {
    errno = EMSGSIZE;
    return -1;
  }
  return 0;
}


int libforks_read_socket_fds(
    int socket_fd,
    void *data, size_t length,
    int *fds, size_t max_fd_count) {
  // See https://man.openbsd.org/CMSG_DATA and https://man.openbsd.org/recv

  if (max_fd_count == 0) {
    // For some reason `sendmsg` fails with ENOMEM on macOS in this special
    // case. Weird. The workaround is dead simple:
    return read_exact(socket_fd, data, length);
  }

  struct iovec iovec = {
    .iov_base = data,
    .iov_len = length,
  };

  char cmsg_buffer[CMSG_BUFFER_SIZE] = {0};
  size_t cmsg_buffer_space = CMSG_SPACE(sizeof(int) * max_fd_count);

  if (cmsg_buffer_space > sizeof cmsg_buffer) {
    errno = ENOMEM;
    return -1;
  }

  struct msghdr msg = {0};
  msg.msg_iov = &iovec;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsg_buffer;
  msg.msg_controllen = cmsg_buffer_space;

  ssize_t recv_res = recvmsg(socket_fd, &msg, 0);
  if (recv_res == -1) {
    return -1;
  }
  if (recv_res != (ssize_t)length ||
      (msg.msg_flags & MSG_TRUNC) ||
      (msg.msg_flags & MSG_CTRUNC)) {
    errno = EMSGSIZE; // there is probably a better way to handle this error
    return -1;
  }

  struct cmsghdr *cmsg;
  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL && max_fd_count; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == SOL_SOCKET &&
        cmsg->cmsg_type == SCM_RIGHTS) {

      char *data_end = (char *)cmsg + cmsg->cmsg_len;
      size_t data_length = data_end - (char *)CMSG_DATA(cmsg);
      assert(data_length % sizeof(int) == 0);
      size_t cmsg_fd_count = data_length / sizeof(int);

      int *cmsg_fds = (int *)CMSG_DATA(cmsg);
      for (size_t i = 0; i < cmsg_fd_count && max_fd_count; i++) {
        *fds = cmsg_fds[i];
        fds++;
        max_fd_count--;
      }
    }
  }

  return 0;
}

int libforks_write_socket_fds(
    int socket_fd,
    void *data, size_t length,
    const int *fds, size_t fd_count) {
  // See https://man.openbsd.org/CMSG_DATA and https://man.openbsd.org/recv

  if (fd_count == 0) {
    // Same macOS issue, same workaround:
    return write_exact(socket_fd, data, length);
  }

  struct iovec iovec = {
    .iov_base = data,
    .iov_len = length,
  };

  char cmsg_buffer[CMSG_BUFFER_SIZE] = {0};
  size_t cmsg_buffer_space = CMSG_SPACE(sizeof(int) * fd_count);

  if (cmsg_buffer_space > sizeof cmsg_buffer) {
    errno = ENOMEM;
    return -1;
  }

  struct msghdr msg = {0};
  msg.msg_iov = &iovec;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsg_buffer;
  msg.msg_controllen = cmsg_buffer_space;

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  assert(cmsg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(int) * fd_count);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * fd_count);

  ssize_t send_res = sendmsg(socket_fd, &msg, 0);
  if (send_res == -1) {
    return -1;
  }
  if (send_res != (ssize_t)length) {
    errno = EMSGSIZE;
    return -1;
  }
  return 0;
}

// XXX Like `serv_DEBUG`, not exactly async-signal-safe but should be
// okay. It’s only used in case of a fatal error.
__attribute__((format(printf, 1, 2)))
static void serv_print_error(const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  // XXX `dprintf` is guaranteed to be async-signal-safe on OpenBSD
  // but not on other systems.
  dprintf(STDERR_FILENO, "libforks server: ");
  vdprintf(STDERR_FILENO, format, ap);
  dprintf(STDERR_FILENO, "\n");
  va_end(ap);
}

static void serv_print_errno(const char *msg) {
  int e = errno;
  char buffer[256];
  assert(msg);
  snprintf(buffer, sizeof buffer, "libforks server: %s", msg);
  errno = e;
  perror(buffer);
}

// It’s difficult for the fork server to report errors
// to the caller through UNIX sockets. I don’t know if we can
// do something better than printing on stderr and exiting.
__attribute__((noreturn)) static void serv_panic() {
  serv_print_error("The fork server encountered a fatal error and will exit");
  abort();
}

static void serv_send(int fd, ServerMessage msg) {
  if (write_exact(fd, &msg, sizeof msg) == -1) {
    serv_print_errno("write");
    serv_panic();
  }
}

static void serv_send_fds(
    int fd,
    ServerMessage msg,
    int *fds,
    size_t fd_count) {
  int write_res = libforks_write_socket_fds(
    fd,
    &msg, sizeof msg,
    fds, fd_count
  );
  if (write_res == -1) {
    serv_print_errno("sendmsg");
    serv_panic();
  }
}

static ClientMessage serv_recv(int fd) {
  ClientMessage msg;

  if (read_exact(fd, &msg, sizeof msg) == -1) {
    serv_print_errno("read");
    serv_panic();
  }

  return msg;
}

// Returns the removed client. Returns NULL if the pid is unknown.
static serv_Client *serv_remove_client(serv_Client **list_ptr, pid_t pid) {
  serv_Client **prev_ptr = list_ptr;
  serv_Client *client = *list_ptr;
  while (client) {
    if (client->pid == pid) {
      *prev_ptr = client->next;
      return client;
    }
    prev_ptr = &((*prev_ptr)->next);
    client = client->next;
  }
  return NULL;
}

// Returns NULL if not found
static serv_Client *serv_find_client_by_socket(serv_Client *l, int socket) {
  assert(socket >= 0);
  while (l) {
    if (l->socket == socket) {
      return l;
    }
    l = l->next;
  }
  return NULL;
}

static void serv_sigchld_handler(int sig_) {
  (void)sig_;

  // This function uses `serv_DEBUG` and `serv_print_errno` which
  // could theoretically be async-signal-unsafe. But that’s only
  // when debugging is enabled or if a fatal error occurs.

  int prev_errno = errno;

  // We know that some children have exited but we don’t know which ones.
  // We can list them by calling `waitpid(-1, …, …)` repeatedly.

  serv_DEBUG("received SIGCHLD\n");

  while (true) {
    int status;
    pid_t child_pid = waitpid(-1, &status, WNOHANG);
    if (child_pid == 0 || (child_pid == -1 && errno == ECHILD)) {
      // no more stopped children
      break;
    }

    if (child_pid == -1) {
      serv_print_errno("waitpid(2) system call in SIGCHLD handler");
      serv_panic();
    }

    assert(WIFEXITED(status) || WIFSIGNALED(status));

    serv_DEBUG("child %d exited, informing main loop\n", (int)child_pid);

    libforks_ExitEvent event = {
      .pid = child_pid,
      .wait_status = status,
    };
    if (write_exact(serv_exit_pipe[WRITE_END], &event, sizeof event) == -1) {
      serv_print_errno("write(2) system call in SIGCHLD handler");
      serv_panic();
    }
  }

  serv_DEBUG("SIGCHLD handling done\n");

  errno = prev_errno;
}

static void serv_uninstall_signal_handler(int signal) {
  struct sigaction sa;
  sa.sa_handler = SIG_DFL;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  if (sigaction(signal, &sa, NULL) == -1) {
    serv_print_errno(NULL);
    serv_panic();
  }
}

__attribute__((noreturn))
static void serv_handle_stop_all_request(
    serv_Client *first_client,
    serv_Client *sender_client) {
  serv_DEBUG("STOP_ALL_REQUEST received\n");

  if (!sender_client->main) {
    // unfortunately we can't use wait(2) with our parent process
    serv_print_error(
      "Deadlock detected!\n"
      "Some libforks functions must be called from the process "
      "that started the fork server."
    );
    serv_panic();
  }

  // we don’t care about SIGCHLD anymore
  serv_uninstall_signal_handler(SIGCHLD);

  // We could send all the signals first and then wait
  // for termination. It’s a bit more complex but it
  // could be significantly faster.

  for (serv_Client *c = first_client; c; c = c->next) {
    if (c->pid != sender_client->pid) {
      serv_DEBUG("sending SIGTERM to %d\n", (int)c->pid);
      if (kill(c->pid, SIGTERM) == -1) {
        if (errno != ESRCH) {
          // ESRCH is normal if the process just exited for some
          // other reason.
          serv_print_errno("kill");
          serv_panic();
        }
      } else {
        serv_DEBUG("waiting for %d\n", (int)c->pid);
        int status;
        if (waitpid(c->pid, &status, 0) == -1) {
          serv_print_errno("waitpid");
          serv_panic();
        }
      }
    }
  }

  serv_DEBUG("all children exited, goodbye!\n");
  exit(0);
}

__attribute__((noreturn))
static void serv_handle_stop_server_only_request(void) {
  serv_DEBUG("STOP_SERVER_ONLY_REQUEST received\n");
  exit(0);
}

static void serv_handle_fork_request(
    const ClientMessage *req,
    serv_Client **first_client_ptr, // in/out
    size_t *client_count_ptr, // in/out
    serv_Client *parent) {
  serv_DEBUG("FORK_REQUEST received\n");

  if (*client_count_ptr == serv_MAX_CLIENTS) {
    ServerMessage res = {
      .type = ServerMessageType_FORK_FAILURE,
      .u = {
        .fork_failure = {
          .error_code = libforks_TOO_MANY_CLIENTS_ERROR,
          .saved_errno = 0,
        },
      },
    };
    serv_send(parent->socket, res);
    return;
  }

  pid_t server_pid = getpid();

  int sockets[2]; // for private child-server communication
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) {
    ServerMessage res = {
      .type = ServerMessageType_FORK_FAILURE,
      .u = {
        .fork_failure = {
          .error_code = libforks_SOCKET_CREATION_ERROR,
          .saved_errno = errno,
        },
      },
    };
    serv_send(parent->socket, res);
    return;
  }
  int server_socket = sockets[0]; // server end
  int child_socket = sockets[1]; // child end

  int user_sockets[2] = {-1, -1}; // for public parent-child communication
  if (req->u.fork_request.create_user_socket) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, user_sockets) == -1) {
      ServerMessage res = {
        .type = ServerMessageType_FORK_FAILURE,
        .u = {
          .fork_failure = {
            .error_code = libforks_SOCKET_CREATION_ERROR,
            .saved_errno = errno,
          },
        },
      };
      serv_send(parent->socket, res);
      goto destroy_socket;
    }
  }
  int parent_user_socket = user_sockets[0]; // parent end
  int child_user_socket = user_sockets[1]; // child end

  pid_t child_pid = fork();
  if (child_pid == -1) {
    ServerMessage res = {
      .type = ServerMessageType_FORK_FAILURE,
      .u = {
        .fork_failure = {
          .error_code = libforks_FORK_ERROR,
          .saved_errno = errno,
        },
      },
    };
    serv_send(parent->socket, res);
    goto destroy_user_socket;
  }

  if (child_pid == 0) {
    // We are in the new child process

    close(server_socket);
    if (parent_user_socket != -1) {
      close(parent_user_socket);
    }

    // Release server resources
    serv_Client *client = *first_client_ptr;
    while (client) {
      serv_Client *next = client->next;
      if (client->exit_fd != -1) {
        close(client->exit_fd);
      }
      if (client->socket != -1) {
        close(client->socket);
      }
      free(client);
      client = next;
    }
    close(serv_exit_pipe[READ_END]);
    close(serv_exit_pipe[WRITE_END]);

    serv_uninstall_signal_handler(SIGTERM);
    serv_uninstall_signal_handler(SIGCHLD);

    ServerConn *child_conn = malloc(sizeof(ServerConn));
    if (!child_conn) {
      // XXX using `serv_*` functions here is not very correct
      // because we are in the child
      serv_print_errno("malloc");
      serv_panic();
    }
    child_conn->server_pid = server_pid;
    child_conn->socket = child_socket;
    libforks_ServerConn conn_p = {.private = child_conn};

    // Inform the parent that we are ready.
    if (write_exact(child_socket, "r", 1) == -1) {
      // XXX not very correct as well
      serv_print_errno("write_exact");
      serv_panic();
    }

    req->u.fork_request.entrypoint(conn_p, child_user_socket);
    exit(0);
  }

  serv_DEBUG("created child process %d\n", (int)child_pid);

  close(child_socket);
  if (child_user_socket != -1) {
    close(child_user_socket);
  }

  serv_Client *client = malloc(sizeof(serv_Client));
  if (!client) {
    serv_print_errno("malloc");
    serv_panic();
  }

  client->pid = child_pid;
  client->main = false;
  client->socket = server_socket;
  client->exit_fd = -1;
  client->next = *first_client_ptr;

  int exit_pipe[2] = {-1, -1};
  if (req->u.fork_request.create_exit_pipe) {
    if (pipe(exit_pipe) == -1) {
      serv_print_errno("pipe");
      serv_panic();
    }
    client->exit_fd = exit_pipe[WRITE_END];
  }
  serv_DEBUG("created exit pipe {%d, %d}\n", exit_pipe[0], exit_pipe[1]);

  *first_client_ptr = client;
  (*client_count_ptr)++;

  int fds_to_send[2];
  size_t fd_count = 0;

  if (parent_user_socket != -1) {
    fds_to_send[fd_count++] = parent_user_socket;
  }
  if (exit_pipe[READ_END] != -1) {
    fds_to_send[fd_count++] = exit_pipe[READ_END];
  }

  // Wait until the child is ready. This is necessary because if
  // libforks_stop() is called just after libforks_fork(), the child
  // process may not have uninstalled its SIGTERM handler yet and
  // may ignore the signal sent by libforks_stop().
  char ready_char;
  if (read_exact(server_socket, &ready_char, 1) == -1 || ready_char != 'r') {
    serv_print_errno("read_exact");
    serv_panic();
  }

  serv_DEBUG("sending %d file descriptor(s)\n", (int)fd_count);
  ServerMessage res = {
    .type = ServerMessageType_FORK_SUCCESS,
    .u = {
      .fork_success = {
        .pid = child_pid,
      },
    },
  };
  serv_send_fds(parent->socket, res, fds_to_send, fd_count);
  if (exit_pipe[READ_END] != -1) {
    close(exit_pipe[READ_END]);
  }
  if (parent_user_socket != -1) {
    close(parent_user_socket);
  }
  return;

destroy_user_socket:
  close(parent_user_socket);
  close(child_user_socket);
destroy_socket:
  close(server_socket);
  close(child_socket);
}

static void serv_handle_kill_all_request(
    const ClientMessage *req,
    serv_Client *first_client,
    serv_Client *sender) {
  serv_DEBUG("KILL_ALL_REQUEST received\n");

  {
    serv_Client *c = first_client;
    while (c) {
      if (c != sender) { // don’t kill the sender!
        if (kill(c->pid, req->u.kill_all_request.signal) == -1) {
          if (errno == ESRCH) {
            // The process has just exited for some other reason.
          } else {
            serv_print_errno("kill");
            serv_panic();
          }
        }
      }

      c = c->next;
    }
  }

  ServerMessage res = {
    .type = ServerMessageType_KILL_SUCCESS,
  };
  serv_send(sender->socket, res);
}

static void serv_handle_eval_request(
    const ClientMessage *req,
    const serv_Client *sender) {
  serv_DEBUG("EVAL_REQUEST received\n");

  req->u.eval_request.function();

  ServerMessage res = {
    .type = ServerMessageType_EVAL_SUCCESS,
  };
  serv_send(sender->socket, res);
}

static void serv_handle_request(
    const ClientMessage *req,
    serv_Client **first_client_ptr, // in/out
    size_t *client_count_ptr, // in/out
    serv_Client *sender) {

  switch (req->type) {
  case ClientMessageType_STOP_ALL_REQUEST:
    serv_handle_stop_all_request(*first_client_ptr, sender);
    break;
  case ClientMessageType_STOP_SERVER_ONLY_REQUEST:
    serv_handle_stop_server_only_request();
    break;
  case ClientMessageType_KILL_ALL_REQUEST:
    serv_handle_kill_all_request(req, *first_client_ptr, sender);
    break;
  case ClientMessageType_FORK_REQUEST:
    serv_handle_fork_request(req, first_client_ptr, client_count_ptr, sender);
    break;
  case ClientMessageType_EVAL_REQUEST:
    serv_handle_eval_request(req, sender);
    break;
  default:
    serv_print_error("Bad message type");
    serv_panic();
  }
}

// Returns how many clients are still connected (i.e. not a zombie)
static unsigned serv_connected_clients(const serv_Client *c) {
  unsigned count = 0;
  while (c) {
    if (c->socket != -1) {
      count++;
    }
    c = c->next;
  }
  return count;
}

// The main loop of the fork server.
__attribute__((noreturn))
static void serv_main(serv_Client *first_client) {
  serv_DEBUG("starting fork server (pid %d)\n", (int)getpid());
  serv_DEBUG("the main client's pid is %d\n", (int)first_client->pid);

  if (signal(SIGPIPE, SIG_IGN)) {
    serv_print_errno(NULL);
    serv_panic();
  }

  if (pipe(serv_exit_pipe) == -1) {
    serv_print_errno("pipe");
    serv_panic();
  }

  // Ignore SIGTERM.
  // Some container environments send SIGTERM to all processes
  // when terminating. It is up to the main process to stop the
  // fork server and its children properly.
  struct sigaction sa;
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGTERM, &sa, NULL) == -1) {
      serv_print_errno(NULL);
      serv_panic();
  }

  // Stay notified of child exits through a SIGCHLD handler and `serv_exit_pipe`
  sa.sa_handler = serv_sigchld_handler;
  sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    serv_print_errno("sigaction");
    serv_panic();
  }

  size_t client_count = 1;

  while (true) {
    nfds_t fd_count = 1;

    struct pollfd poll_fds[1 + serv_MAX_CLIENTS];

    poll_fds[0].fd = serv_exit_pipe[READ_END];
    poll_fds[0].events = POLLIN | POLLPRI;
    poll_fds[0].revents = 0;

    for (serv_Client *c = first_client; c; c = c->next) {
      if (c->socket == -1) {
        continue; // “zombie” disconnected client
      }

      assert(fd_count <= (sizeof(poll_fds) / sizeof(struct pollfd)));
      struct pollfd *pollfd = poll_fds + fd_count;
      pollfd->fd = c->socket;
      pollfd->events = POLLIN | POLLPRI;
      pollfd->revents = 0;
      fd_count++;
    }

    serv_DEBUG("polling…\n");
    if (poll(poll_fds, fd_count, -1) == -1) {
      if (errno == EINTR) {
        serv_DEBUG("poll(2) has been interrupted by a signal\n");
        // poll failed because a signal has been received.
        // Just restart it.
        // (SA_RESTART does not work with poll(2))
        continue;
      }

      serv_print_errno("poll");
      serv_panic();
    }

    if (poll_fds[0].revents) {
      // A SIGCHLD signal has been received.

      assert(
        (poll_fds[0].revents & POLLIN) ||
        (poll_fds[0].revents & POLLPRI)
      );

      libforks_ExitEvent event;
      if (read_exact(serv_exit_pipe[READ_END], &event, sizeof event) == -1) {
        serv_print_errno("read_exact");
        serv_panic();
      }

      serv_DEBUG("main loop knows that %d has exited\n", (int)event.pid);

      serv_Client *client = serv_remove_client(&first_client, event.pid);
      assert(client);
      client_count--;

      if (client->exit_fd != -1) {
        serv_DEBUG("informing parent that %d has exited\n", (int)event.pid);
        if (write_exact(client->exit_fd, &event, sizeof event) == -1) {
          if (errno == EPIPE) {
            // Ignore the error because that’s pretty much normal and
            // expected, it happens if the client has closed the pipe
            // or exited.
            // (SIGPIPE is already ignored)
          } else {
            serv_print_errno("exit pipe write");
            serv_panic();
          }
        }
      }

      if (serv_connected_clients(first_client) == 0) {
        serv_DEBUG("no more connected clients, goodbye!\n");
        exit(0);
      }

      if (client->socket != -1) {
        close(client->socket);
      }
      if (client->exit_fd != -1) {
        close(client->exit_fd);
      }
      free(client);
    }

    for (size_t i = 1; i < fd_count; i++) {
      struct pollfd *pollfd = poll_fds + i;
      if (!pollfd->revents) {
        continue;
      }

      serv_Client *sender = serv_find_client_by_socket(
        first_client,
        pollfd->fd
      );
      if (!sender) {
        // the client has just exited and has been removed by the
        // libforks_ExitEvent handler
        continue;
      }

      if ((pollfd->revents & POLLERR) || (pollfd->revents & POLLNVAL)) {
        serv_print_error("socket read error (with client %d)",
            (int)sender->pid);
        serv_panic();
      }

      if (pollfd->revents & POLLHUP) {
        serv_DEBUG("client %d closed its socket\n", (int)sender->pid);
        // The sender may or may not have exited. We can’t forget it right
        // now because we may need its `exit_fd` to notify its parent
        // when it will actually exits, so we mark it as a “zombie” by
        // setting its `socket` to -1 and wait for a SIGCHLD signal.
        assert(sender->socket != -1);
        close(sender->socket);
        sender->socket = -1;
        if (serv_connected_clients(first_client) == 0) {
          serv_DEBUG("no more connected clients, goodbye!\n");
          exit(0);
        }
        continue;
      }

      assert(
        (pollfd->revents & POLLIN) ||
        (pollfd->revents & POLLPRI)
      );

      assert(sender->socket == pollfd->fd);
      ClientMessage req = serv_recv(pollfd->fd);
      serv_handle_request(&req, &first_client, &client_count, sender);
    }
  }
}

libforks_Result libforks_start(libforks_ServerConn *conn_ptr) {
  libforks_Result res;
  pid_t main_proc_pid = getpid();

  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) {
    res = libforks_SOCKET_CREATION_ERROR;
    goto exit;
  }

  int server_pid = fork();
  if (server_pid == -1) {
    res = libforks_FORK_ERROR;
    goto del_sockets;
  }

  if (server_pid == 0) {
    // this is the server process
    close(sockets[1]);

    serv_Client *client = malloc(sizeof(serv_Client));
    if (!client) {
      serv_print_errno("malloc");
      serv_panic();
    }
    client->pid = main_proc_pid;
    client->main = true;
    client->socket = sockets[0];
    client->exit_fd = -1;
    client->next = NULL;

    serv_main(client);
    abort(); // not reached
  }

  ServerConn *conn = malloc(sizeof(ServerConn));
  if (!conn) {
    res = libforks_MALLOC_ERROR;
    goto kill_server;
  }

  close(sockets[0]);
  conn->server_pid = server_pid;
  conn->socket = sockets[1];

  conn_ptr->private = conn;
  res = libforks_OK;
  goto exit;

kill_server:
  kill(server_pid, SIGKILL);

del_sockets:
  close(sockets[0]);
  close(sockets[1]);

exit:
  return res;
}

pid_t libforks_get_server_pid(libforks_ServerConn conn_p) {
  const ServerConn *conn = conn_p.private;
  return conn->server_pid;
}


libforks_Result libforks_fork(
    libforks_ServerConn conn_p,
    pid_t *pid_ptr, // out
    int *socket_fd_ptr, // out
    int *exit_fd_ptr, // out
    void (*entrypoint)(libforks_ServerConn conn, int socket_fd)
  ) {

  ServerConn *conn = conn_p.private;

  ClientMessage req = {
    .type = ClientMessageType_FORK_REQUEST,
    .u = {
      .fork_request = {
        .create_user_socket = socket_fd_ptr != NULL,
        .create_exit_pipe = exit_fd_ptr != NULL,
        .entrypoint = entrypoint,
      },
    },
  };

  if (write_exact(conn->socket, &req, sizeof req) == -1) {
    return libforks_WRITE_ERROR;
  }

  ServerMessage res;
  int received_fds[2] = {-1, -1};
  int read_res = libforks_read_socket_fds(
    conn->socket,
    &res, sizeof res,
    received_fds, 2
  );
  if (read_res == -1) {
    return libforks_READ_ERROR;
  }

  if (res.type == ServerMessageType_FORK_FAILURE) {
    assert(res.u.fork_failure.error_code != libforks_OK);
    errno = res.u.fork_failure.saved_errno;
    return res.u.fork_failure.error_code;
  }

  assert(res.type == ServerMessageType_FORK_SUCCESS);

  if (pid_ptr) {
    *pid_ptr = res.u.fork_success.pid;
  }

  unsigned i = 0;
  if (socket_fd_ptr) {
    *socket_fd_ptr = received_fds[i++];
  }
  if (exit_fd_ptr) {
    *exit_fd_ptr = received_fds[i++];
  }

  return libforks_OK;
}

// waits until the server exits
static libforks_Result finalize_stop(ServerConn *conn) {
  int status;
  if (waitpid(conn->server_pid, &status, 0) == -1) {
    return libforks_WAIT_ERROR;
  }

  assert(WIFEXITED(status) || WIFSIGNALED(status));

  close(conn->socket); // ignore error
  free(conn);
  return libforks_OK;
}

libforks_Result libforks_stop_server_only(libforks_ServerConn conn_p) {
  ServerConn *conn = conn_p.private;

  ClientMessage req = {
    .type = ClientMessageType_STOP_SERVER_ONLY_REQUEST,
  };

  if (write_exact(conn->socket, &req, sizeof req) == -1) {
    return libforks_WRITE_ERROR;
  }

  return finalize_stop(conn);
}

libforks_Result libforks_stop(libforks_ServerConn conn_p) {
  ServerConn *conn = conn_p.private;

  ClientMessage req = {
    .type = ClientMessageType_STOP_ALL_REQUEST,
  };
  if (write_exact(conn->socket, &req, sizeof req) == -1) {
    return libforks_WRITE_ERROR;
  }

  return finalize_stop(conn);
}

libforks_Result libforks_free_conn(libforks_ServerConn conn_p) {
  ServerConn *conn = conn_p.private;
  close(conn->socket); // ignore error
  free(conn);
  return libforks_OK;
}

libforks_Result libforks_kill_all(libforks_ServerConn conn_p, int signal) {
  ServerConn *conn = conn_p.private;

  ClientMessage req = {
    .type = ClientMessageType_KILL_ALL_REQUEST,
    .u = {
      .kill_all_request = {
        .signal = signal
      },
    },
  };
  if (write_exact(conn->socket, &req, sizeof req) == -1) {
    return libforks_WRITE_ERROR;
  }

  ServerMessage res;
  if (read_exact(conn->socket, &res, sizeof res) == -1) {
    return libforks_READ_ERROR;
  }

  assert(res.type == ServerMessageType_KILL_SUCCESS);
  return libforks_OK;
}

libforks_Result libforks_eval(libforks_ServerConn conn_p, void (*function)(void)) {
  ServerConn *conn = conn_p.private;

  ClientMessage req = {
    .type = ClientMessageType_EVAL_REQUEST,
    .u = {
      .eval_request = {
        .function = function
      },
    },
  };
  if (write_exact(conn->socket, &req, sizeof req) == -1) {
    return libforks_WRITE_ERROR;
  }

  ServerMessage res;
  if (read_exact(conn->socket, &res, sizeof res) == -1) {
    return libforks_READ_ERROR;
  }

  assert(res.type == ServerMessageType_EVAL_SUCCESS);
  return libforks_OK;
}


const char *libforks_result_string(libforks_Result result) {
  switch (result) {
#define E(name) case libforks_##name: return #name;
    E(OK)
    E(READ_ERROR)
    E(WRITE_ERROR)
    E(SOCKET_CREATION_ERROR)
    E(MALLOC_ERROR)
    E(FORK_ERROR)
    E(WAIT_ERROR)
    E(TOO_MANY_CLIENTS_ERROR)
  }
  abort();
}
