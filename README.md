<!-- AUTOMATICALLY GENERATED DO NOT EDIT -->

⚠️*: still a work in progress, this library is experimental*

libforks: A solution to use fork(2) in multithreaded programs

It is well known in the UNIX world that the `fork(2)` system
call is dangerous in a multithreaded environment and should be
used with great care, especially if `execve(2)` is not called
immediately after: Since only the main thread is duplicated,
other threads do not exist and some mutexes may be locked
forever. Unfortunately, there is no way to unlock them and the
`pthread_atfork()` function isn’t any useful in this scenario.

One solution to this issue is to use a _fork server_. The big
picture is to call `fork(2)` early at the beginning of the
program, before the creation of other threads in order to create
the fork server process. The fork server process is
single-threaded and communicates with the main program through
UNIX sockets. When the main program wants to spawn another
process, it sends a message to the fork server and the fork server
calls `fork(2)` on behalf of the main program. This library also
allows the parent process to be notified when a child exits, to
setup UNIX sockets to communicate with the child and to transfer
file descriptors between arbitrary processes.

Of course, this library is not a drop-in replacement for existing
calls to `fork(2)`.

Fork servers are used in the real world by a few programs including
CPython and the Erlang Run-Time System, but they have their own
specific implementation. This library is basically the same thing
bundled to be reusable in other programs.

This library is written in C99 (hey, it’s been 20 years!) and
will not compile in C89.

# Examples

Please take a look at the `examples/` directory.

# Installation

TODO: Talk about compiling the SQLite-like single source file

# Data types

```c
typedef struct { void *private; } libforks_ServerConn;
```

Represents a connection to a fork server. Must be initialized
by `libforks_start` before being used in other functions.

```c
typedef struct {
  pid_t pid; // Child process pid
  int wait_status; // Status retured by `waitpid(2)`
} libforks_ExitEvent;
```

Event emitted on the dedicated file descriptor when a child
process exits. See `libforks_fork` for further details.

-----

```c
typedef enum {
  libforks_OK = 0, // No error
  libforks_READ_ERROR = -1,
  libforks_WRITE_ERROR = -2,
  libforks_KILL_ERROR = -3,
  libforks_SOCKET_CREATION_ERROR = -4,
  libforks_MALLOC_ERROR = -5,
  libforks_FORK_ERROR = -6,
  libforks_WAIT_ERROR = -7,
  libforks_STOP_ERROR = -8,
  libforks_PIPE_CREATION_ERROR = -9,
} libforks_Result;
```

Errors codes used by this library. More codes may be added in
the future. `libforks_OK` means “no error”.

-----

# Functions

TODO: Talk about thread-safety. Write some examples and tests. I
don’t think that all the functions are thread-safe (they must be
protected by mutexes).

-----

```c
libforks_Result libforks_start(libforks_ServerConn *conn_ptr);
```

Start the fork server.

This function initializes the `ServerConn` struct pointed to by
`conn_ptr`. Most of the following functions need an initialized
`ServerConn`.

Child processes will be forked from this point so it’s a bit like
if a copy of the calling process will be saved and frozen here
and revived each time that someone calls `libforks_fork`. The caller
process should have only one thread.

One process can start many fork servers and one fork server
can be shared by many different processes, a process can call
this function many times in order to start many different
fork servers.

-----

```c
libforks_Result libforks_kill_all(libforks_ServerConn conn, int signal);
```

Send the given signal to all the running children.

-----

```c
libforks_Result libforks_wait(
  libforks_ServerConn conn,
  pid_t pid,
  int *stat_loc, // out
  int options,
  struct rusage *rusage // out
);
```

Wait until the specified child processes exit.

TODO

Warning: The fork server is single-threaded and will be entirely
blocked until this function returns.

-----

```c
libforks_Result libforks_wait_all(libforks_ServerConn conn);
```

TODO

Warning: The fork server is single-threaded and will be entirely
blocked until this function returns.

-----

```c
libforks_Result libforks_stop(libforks_ServerConn conn, bool wait);
```

Stop the fork server and send SIGTERM to every child process.

If `wait` is true, this function does not return until all the
children have actually exited. If `wait` is false, this function
returns immediately, even if some children have not exited yet.

Use `libforks_kill_all` to send a different signal that SIGTERM.

This function invalidates the given ServerConn. It must be called
from the process that started the fork server.

```c
libforks_Result libforks_stop_server_only(libforks_ServerConn conn);
```

Stop the fork server. Does not stop running children!

This function invalidates the given ServerConn. It must be called
from the process that started the fork server.

TODO: Write tests for this one

-----

```c
libforks_Result libforks_fork(
  libforks_ServerConn conn,
  pid_t *pid_ptr, // out
  int *socket_fd_ptr, // out
  int *exit_fd_ptr, // out
  void (*entrypoint)(libforks_ServerConn conn, int socket_fd)
);
```

Forks the server process.

If `*pid_ptr` is not NULL, the pid of the new process will be
written to `*pid_ptr`.
If `*exit_fd_ptr` is not NULL, a readable “exit file descriptor”
will be written to `*exit_fd_ptr`. When the child process will
exit, a `libforks_ExitEvent` struct will be readable on this file
descriptor. Functions like `poll(2)` can be used on this file
descriptor. The caller should close it after use.

Of course, this does not behave exactly like a plain old call
to fork(2):
- The parent process of the new child process is the fork server
and not the caller.
- The new child process will not be a copy of the caller at
the time when `libforks_fork` is called, but when `libforks_start`
was called. In other words, `libforks_start` saves the state of
the process and `libforks_fork` restores it.

The ServerConn is sent to the new process. The new process can
use the fork server exactly like the parent, except it should not stop it.

The `entrypoint` function pointer must be available when `libforks_start`
was called so if you want to load it in the caller process with something
like `dlopen`, do it before `libforks_start`. Or do it after the fork
in the child process.

-----

```c
int libforks_read_socket_fds(
    int socket_fd,
    void *data, size_t length,
    int *fds, size_t max_fd_count);

int libforks_write_socket_fds(
    int socket_fd,
    void *data, size_t length,
    const int *fds, size_t fd_count);
```

Low-level utility functions that can be used to transfer PIDs between
arbitrary processes. These are a bit unrelated to the previous
functions. They are made available because they are used internally.

`max_fd_count`: Maximum number of file descriptors to receive. Should
match the size of the array at `fds`.

-----

# License

```
Copyright Ericsson AB 1996-2018. All Rights Reserved.
Copyright 2019 Antoine Motet

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this library except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

