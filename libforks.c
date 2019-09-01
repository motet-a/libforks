// Copyright Ericsson AB 1996-2018. All Rights Reserved.
// Copyright 2019 Antoine Motet
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


#ifdef LIBFORK_DEBUG
#  define serv_DEBUG(...) (fprintf(stderr, "libforks server: " __VA_ARGS__))
#else
#  define serv_DEBUG(...)
#endif


// There’s a protocol between the fork server and its clients
typedef enum {
  ClientMessageType_FORK_REQUEST,
  ClientMessageType_STOP_SERVER_ONLY_REQUEST,
  ClientMessageType_STOP_ALL_REQUEST,
  ClientMessageType_KILL_ALL_REQUEST,
  ClientMessageType_EVAL_REQUEST,
} ClientMessageType;

typedef struct {
  ClientMessageType type;
  pid_t pid; // The pid of the client that sends the message
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
} ClientMessage;

typedef enum {
  ServerMessageType_FORK_SUCCESS,
  ServerMessageType_FORK_FAILURE,
  ServerMessageType_KILL_SUCCESS,
  ServerMessageType_STOP_SUCCESS,
  ServerMessageType_EVAL_SUCCESS,
} ServerMessageType;

typedef struct {
  ServerMessageType type;
  union {
    struct {
      pid_t pid;
      // user socket fd and exit fd are transmitted in headers along
      // this message
    } fork_success;

    struct {
      libforks_Result error_code;
    } fork_failure;
  } u;
} ServerMessage;


// There is one different instance of this struct in each client process.
typedef struct {
  int server_pid;
  int incoming_socket_in; // Used to send data to the server. Shared.
  int outgoing_socket_out; // Used to receive data from the server. Not shared, each process has its own.
} ServerConn;

struct serv_Client;
typedef struct serv_Client serv_Client;

// A client connected to the fork server. Keep in mind that each child process
// is also a client.
struct serv_Client {
  pid_t pid;
  serv_Client *parent; // NULL for the process that called `libforks_start()`
  int outgoing_socket_in; // used to send messages from the server to the client
  int exit_fd; // -1 for the main process
  serv_Client *next; // linked list
};



// The writeable end of the “exit pipe”. Used by the SIGCHLD handler (inside
// the server process) to communicate exit events to the main server loop.
//
// Never used in client and child processes.
static int serv_exit_pipe_in;


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


static int safe_read(int fd, void *data, size_t length) {
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

static int safe_write(int fd, const void *data, size_t length) {
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
    return safe_read(socket_fd, data, length);
  }

  struct iovec iovec = {
    .iov_base = data,
    .iov_len = length,
  };

  char cmsg_buffer[CMSG_SPACE(sizeof(int) * max_fd_count)];
  memset(cmsg_buffer, 0, sizeof cmsg_buffer);

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iovec;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsg_buffer;
  msg.msg_controllen = sizeof(cmsg_buffer);

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
    return safe_write(socket_fd, data, length);
  }

  struct iovec iovec = {
    .iov_base = data,
    .iov_len = length,
  };

  char cmsg_buffer[CMSG_SPACE(sizeof(int) * fd_count)];
  memset(cmsg_buffer, 0, sizeof cmsg_buffer);

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iovec;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsg_buffer;
  msg.msg_controllen = sizeof(cmsg_buffer);

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

static void serv_print_error(const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  fprintf(stderr, "libforks server: ");
  vfprintf(stderr, format, ap);
  fprintf(stderr, "\n");
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
  if (safe_write(fd, &msg, sizeof msg) == -1) {
    serv_print_errno("write");
    serv_panic();
  }
}

static void serv_send_fds(int fd, ServerMessage msg, int *fds, size_t fd_count) {
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

  if (safe_read(fd, &msg, sizeof msg) == -1) {
    serv_print_errno("read");
    serv_panic();
  }

  return msg;
}

// Returns the removed client. Panics if the given pid is unknown.
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
  serv_panic();
}

// Finds a client by pid. Panics if not found.
static serv_Client *serv_find_client(serv_Client *l, pid_t pid) {
  while (l) {
    if (l->pid == pid) {
      return l;
    }
    l = l->next;
  }
  serv_panic();
}


static void serv_sigchld_handler(int sig_) {
  (void)sig_;

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

    serv_DEBUG("child %d exited, informing main loop\n", child_pid);

    libforks_ExitEvent event = {
      .pid = child_pid,
      .wait_status = status,
    };
    if (safe_write(serv_exit_pipe_in, &event, sizeof event) == -1) {
      serv_print_errno("write(2) system call in SIGCHLD handler");
      serv_panic();
    }
  }

  serv_DEBUG("SIGCHLD handling done\n");

  errno = prev_errno;
}

static void serv_do_stop(serv_Client *sender_client) {
  serv_send(
    sender_client->outgoing_socket_in,
    (ServerMessage){
      .type = ServerMessageType_STOP_SUCCESS,
    }
  );

  serv_DEBUG("goodbye!\n");
  exit(0);
}

static void serv_handle_stop_all_request(
    serv_Client **first_client_ptr,
    serv_Client *sender_client) {
  serv_DEBUG("STOP_ALL_REQUEST received\n");

  for (serv_Client *c = *first_client_ptr; c; c = c->next) {
    if (c->pid != sender_client->pid) {
      serv_DEBUG("sending SIGTERM to %d\n", c->pid);
      if (kill(c->pid, SIGTERM) == -1) {
        if (errno != ESRCH) {
          // ESRCH is normal if the process just exited for some
          // other reason.
          serv_print_errno("kill");
          serv_panic();
        }
      }
    }
  }

  if (sender_client->parent) {
    // TODO: I wonder if we could remove this restriction if we call
    // `wait` repeatedly
    serv_print_error(
      "Deadlock detected!\n"
      "You have called a libforks function from a child process that must be called from the process "
      "that started the fork server from a child process.\n"
    );
    serv_panic();
  }

  serv_DEBUG("waiting until children exit");
  int status;
  if (wait(&status) == -1) {
    if (errno != ECHILD) {
      serv_print_errno("wait");
      serv_panic();
    }
  }
  serv_DEBUG("all children exited\n");

  serv_do_stop(sender_client);
}

static void serv_uninstall_signal_handler(int signal) {
  struct sigaction sa;
  sa.sa_handler = SIG_DFL;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  if (sigaction(signal, &sa, 0) == -1) {
      serv_print_errno(NULL);
      serv_panic();
  }
}

static void serv_handle_fork_request(
    const ClientMessage *req,
    serv_Client **first_client_ptr,
    serv_Client *parent,
    int incoming_socket_out,
    int incoming_socket_in) {
  serv_DEBUG("FORK_REQUEST received\n");

  int outgoing_sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, outgoing_sockets) == -1) {
    serv_print_errno("socketpair");
    serv_panic();
  }

  int user_sockets[2] = {-1, -1};
  if (req->u.fork_request.create_user_socket) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, user_sockets) == -1) {
      serv_print_errno("socketpair");
      serv_panic();
    }
  }
  int user_socket_parent = user_sockets[0]; // parent end
  int user_socket_child = user_sockets[1]; // child end

  pid_t child_pid = fork();
  if (child_pid == -1) {
    serv_print_errno("fork");
    serv_panic();
  }

  if (child_pid == 0) {
    close(incoming_socket_out);
    close(outgoing_sockets[0]);
    if (user_socket_parent != -1) {
      close(user_socket_parent);
    }

    // release server resources
    serv_Client *client = *first_client_ptr;
    while (client) {
      serv_Client *next = client->next;
      if (client->exit_fd != -1) {
        close(client->exit_fd);
      }
      close(client->outgoing_socket_in);
      free(client);
      client = next;
    }
    close(serv_exit_pipe_in);

    serv_uninstall_signal_handler(SIGTERM);
    serv_uninstall_signal_handler(SIGCHLD);

    ServerConn child_conn = {
      .incoming_socket_in = incoming_socket_in,
      .outgoing_socket_out = outgoing_sockets[1],
    };

    libforks_ServerConn conn_p = {
      .private = &child_conn,
    };

    req->u.fork_request.entrypoint(conn_p, user_socket_child);
    exit(0);
  }

  serv_DEBUG("created child process %d\n", child_pid);

  close(outgoing_sockets[1]);
  if (user_socket_child != -1) {
    close(user_socket_child);
  }

  serv_Client *client = malloc(sizeof(serv_Client));
  if (!client) {
    serv_print_errno("malloc");
    serv_panic();
  }

  client->pid = child_pid;
  client->parent = parent;
  client->outgoing_socket_in = outgoing_sockets[0];
  client->exit_fd = -1;
  client->next = *first_client_ptr;

  int exit_pipe[2] = {-1, -1};
  if (req->u.fork_request.create_exit_pipe) {
    if (pipe(exit_pipe) == -1) {
      serv_print_errno("pipe");
      serv_panic();
    }
    client->exit_fd = exit_pipe[1];
  }
  int exit_out = exit_pipe[0];

  *first_client_ptr = client;

  int fds_to_send[2];
  size_t fd_count = 0;

  if (user_socket_parent != -1) {
    fds_to_send[fd_count++] = user_socket_parent;
  }
  if (exit_out != -1) {
    fds_to_send[fd_count++] = exit_out;
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
  serv_send_fds(parent->outgoing_socket_in, res, fds_to_send, fd_count);
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
  serv_send(sender->outgoing_socket_in, res);
}

static void serv_handle_eval_request(
    const ClientMessage *req,
    const serv_Client *sender) {
  serv_DEBUG("EVAL_REQUEST received\n");

  req->u.eval_request.function();

  ServerMessage res = {
    .type = ServerMessageType_EVAL_SUCCESS,
  };
  serv_send(sender->outgoing_socket_in, res);
}

// The main loop of the fork server.
__attribute__((noreturn))
static void serv_main(serv_Client *first_client, int incoming_socket_out, int incoming_socket_in) {
  serv_DEBUG("starting fork server (pid %d)\n", getpid());
  serv_DEBUG("the main client's pid is %d\n", first_client->pid);

  int exit_pipe[2];
  if (pipe(exit_pipe) == -1) {
    serv_print_errno("pipe");
    serv_panic();
  }
  int exit_pipe_out = exit_pipe[0];
  serv_exit_pipe_in = exit_pipe[1];

  // Ignore SIGTERM.
  // Some container environments send SIGTERM to all processes
  // when terminating. It is up to the main process to stop the
  // fork server and its children properly.
  struct sigaction sa;
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGTERM, &sa, 0) == -1) {
      serv_print_errno(NULL);
      serv_panic();
  }

  // Stay notified of child exits through a SIGCHLD handler and `exit_pipe`
  sa.sa_handler = serv_sigchld_handler;
  sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    serv_print_errno("sigaction");
    serv_panic();
  }

  while (true) {
    // We read data from both exit_pipe_out and incoming_socket_out
    struct pollfd poll_fds[] = {
      {
        .fd = exit_pipe_out,
        .events = POLLIN,
        .revents = 0,
      },
      {
        .fd = incoming_socket_out,
        .events = POLLIN,
        .revents = 0,
      }
    };

    serv_DEBUG("polling…\n");
    if (poll(poll_fds, sizeof(poll_fds) / sizeof(struct pollfd), -1) == -1) {
      if (errno == EINTR) {
        // poll failed because a signal has been received.
        // Just restart it.
        // (SA_RESTART does not work with poll(2))
        continue;
      }

      serv_print_errno("poll");
      serv_panic();
    }

    if (poll_fds[0].revents) {
      libforks_ExitEvent event;
      if (safe_read(exit_pipe_out, &event, sizeof event) == -1) {
        serv_print_errno("read");
        serv_panic();
      }

      serv_DEBUG("main loop knows that %d has exited\n", event.pid);

      serv_Client *child_client = serv_remove_client(&first_client, event.pid);
      if (child_client->exit_fd != -1) {
        serv_DEBUG("informing parent that %d has exited\n", event.pid);
        // there’s no error if the read end of the pipe is closed
        // by the parent (at least on macOS)
        if (safe_write(child_client->exit_fd, &event, sizeof event) == -1) {
          serv_print_errno("write");
          serv_panic();
        }
      }

      close(child_client->outgoing_socket_in);
      free(child_client);
    }

    if (poll_fds[1].revents) {
      ClientMessage req = serv_recv(incoming_socket_out);

      serv_Client *sender = serv_find_client(first_client, req.pid);
      assert(sender);

      if (req.type == ClientMessageType_STOP_ALL_REQUEST) {
        serv_handle_stop_all_request(&first_client, sender);
      } else if (req.type == ClientMessageType_STOP_SERVER_ONLY_REQUEST) {
        serv_do_stop(sender);
      } else if (req.type == ClientMessageType_KILL_ALL_REQUEST) {
        serv_handle_kill_all_request(&req, first_client, sender);
      } else if (req.type == ClientMessageType_FORK_REQUEST) {
        serv_handle_fork_request(
          &req,
          &first_client,
          sender,
          incoming_socket_out,
          incoming_socket_in
        );
      } else if (req.type == ClientMessageType_EVAL_REQUEST) {
        serv_handle_eval_request(&req, sender);
      } else {
        serv_print_error("Bad message type");
        serv_panic();
      }
    }
  }
}

libforks_Result libforks_start(libforks_ServerConn *conn_ptr) {
  libforks_Result res;
  pid_t main_proc_pid = getpid();

  int incoming_sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, incoming_sockets) == -1) {
    res = libforks_SOCKET_CREATION_ERROR;
    goto exit;
  }

  int outgoing_sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, outgoing_sockets) == -1) {
    res = libforks_SOCKET_CREATION_ERROR;
    goto del_incoming_sockets;
  }

  int server_pid = fork();
  if (server_pid == -1) {
    res = libforks_FORK_ERROR;
    goto del_sockets;
  }

  if (server_pid == 0) {
    // this is the server process
    close(outgoing_sockets[1]);

    serv_Client *client = malloc(sizeof(serv_Client));
    if (!client) {
      serv_print_errno("malloc");
      serv_panic();
    }
    client->pid = main_proc_pid;
    client->parent = NULL;
    client->outgoing_socket_in = outgoing_sockets[0];
    client->exit_fd = -1;
    client->next = NULL;

    serv_main(client, incoming_sockets[1], incoming_sockets[0]);
    abort(); // not reached
  }

  ServerConn *conn = malloc(sizeof(ServerConn));
  if (!conn) {
    res = libforks_MALLOC_ERROR;
    goto kill_server;
  }

  close(incoming_sockets[1]);
  close(outgoing_sockets[0]);
  conn->server_pid = server_pid;
  conn->incoming_socket_in = incoming_sockets[0];
  conn->outgoing_socket_out = outgoing_sockets[1];

  conn_ptr->private = conn;
  res = libforks_OK;
  goto exit;

kill_server:
  kill(server_pid, SIGKILL);

del_sockets:
  close(outgoing_sockets[0]);
  close(outgoing_sockets[1]);

del_incoming_sockets:
  close(incoming_sockets[0]);
  close(incoming_sockets[1]);

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
    .pid = getpid(),
    .u = {
      .fork_request = {
        .create_user_socket = socket_fd_ptr != NULL,
        .create_exit_pipe = exit_fd_ptr != NULL,
        .entrypoint = entrypoint,
      },
    },
  };

  if (safe_write(conn->incoming_socket_in, &req, sizeof req) == -1) {
    return libforks_WRITE_ERROR;
  }

  ServerMessage res;
  int received_fds[2] = {-1, -1};
  int read_res = libforks_read_socket_fds(
    conn->outgoing_socket_out,
    &res, sizeof res,
    received_fds, 2
  );
  if (read_res == -1) {
    return libforks_READ_ERROR;
  }

  if (res.type == ServerMessageType_FORK_FAILURE) {
    assert(res.u.fork_failure.error_code != libforks_OK);
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

// Reads the server response and waits until the server exits
static libforks_Result finalize_stop(ServerConn *conn) {
  ServerMessage res;
  if (safe_read(conn->outgoing_socket_out, &res, sizeof res) == -1) {
    return libforks_READ_ERROR;
  }

  assert(res.type == ServerMessageType_STOP_SUCCESS);

  int status;
  if (waitpid(conn->server_pid, &status, 0) == -1) {
    return libforks_WAIT_ERROR;
  }

  assert(WIFEXITED(status) || WIFSIGNALED(status));

  close(conn->incoming_socket_in);
  close(conn->outgoing_socket_out);
  free(conn);
  return libforks_OK;
}

libforks_Result libforks_stop_server_only(libforks_ServerConn conn_p) {
  ServerConn *conn = conn_p.private;

  ClientMessage req = {
    .type = ClientMessageType_STOP_SERVER_ONLY_REQUEST,
    .pid = getpid(),
  };

  if (safe_write(conn->incoming_socket_in, &req, sizeof req) == -1) {
    return libforks_WRITE_ERROR;
  }

  return finalize_stop(conn);
}

libforks_Result libforks_stop(libforks_ServerConn conn_p) {
  ServerConn *conn = conn_p.private;

  ClientMessage req = {
    .type = ClientMessageType_STOP_ALL_REQUEST,
    .pid = getpid(),
  };
  if (safe_write(conn->incoming_socket_in, &req, sizeof req) == -1) {
    return libforks_WRITE_ERROR;
  }

  return finalize_stop(conn);
}

libforks_Result libforks_free_conn(libforks_ServerConn conn_p) {
  ServerConn *conn = conn_p.private;
  if (close(conn->incoming_socket_in) ||
      close(conn->outgoing_socket_out)) {
    return libforks_CLOSE_ERROR;
  }
  return libforks_OK;
}

libforks_Result libforks_kill_all(libforks_ServerConn conn_p, int signal) {
  ServerConn *conn = conn_p.private;

  ClientMessage req = {
    .type = ClientMessageType_KILL_ALL_REQUEST,
    .pid = getpid(),
    .u = {
      .kill_all_request = {
        .signal = signal
      },
    },
  };
  if (safe_write(conn->incoming_socket_in, &req, sizeof req) == -1) {
    return libforks_WRITE_ERROR;
  }

  ServerMessage res;
  if (safe_read(conn->outgoing_socket_out, &res, sizeof res) == -1) {
    return libforks_READ_ERROR;
  }

  assert(res.type == ServerMessageType_KILL_SUCCESS);
  return libforks_OK;
}

libforks_Result libforks_eval(libforks_ServerConn conn_p, void (*function)(void)) {
  ServerConn *conn = conn_p.private;

  ClientMessage req = {
    .type = ClientMessageType_EVAL_REQUEST,
    .pid = getpid(),
    .u = {
      .eval_request = {
        .function = function
      },
    },
  };
  if (safe_write(conn->incoming_socket_in, &req, sizeof req) == -1) {
    return libforks_WRITE_ERROR;
  }

  ServerMessage res;
  if (safe_read(conn->outgoing_socket_out, &res, sizeof res) == -1) {
    return libforks_READ_ERROR;
  }

  assert(res.type == ServerMessageType_EVAL_SUCCESS);
  return libforks_OK;
}


