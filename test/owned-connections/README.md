# Maintained server ownership hooks

This patch starts from upstream v0.54.1
(`9d6a7ee2c1aaeb1fd9ae15d14f06f487149d147f`). It provides explicit connection
ownership for embedding an HTTP server beside other runtimes in one process.

Define `CPPHTTPLIB_OWNED_SERVER_SOCKETS` to enable the connection hooks and
owned listener. It changes `Server`'s private layout and virtual processor;
all translation units using these server objects must enable the same option.
Without it, ordinary builds retain the upstream Server ABI and listener path.
The Orocos HTTP build enables it automatically and consumes the header privately.

`CPPHTTPLIB_NO_DEFAULT_SIGPIPE` disables the server constructor's process-wide
SIGPIPE change. The default remains unchanged. On POSIX the embedding runtime
must block SIGPIPE on its listener thread before construction, let its workers
inherit the mask, and keep the mask through TLS cleanup. Plain writes can also
use `CPPHTTPLIB_SEND_FLAGS=MSG_NOSIGNAL` where available.

`Server::set_connection_handler` receives a shared `ServerConnection` before
the connection is offered to the task queue. `cancel()` disposes a queued
socket without HTTP parsing or TLS negotiation. It interrupts an active socket
without closing its descriptor until the worker finishes all socket and TLS
use. Retaining a closed handle is safe; cancelling it cannot affect a later
connection that reuses the descriptor. The task also owns cleanup when a queue
rejects or discards work. A hook must not block the listener and must keep its
own registry bounded, remove closed entries, and reject arrivals during stop.

`Server::stop()` invalidates the listener for admission immediately. The accept
loop owns final close while active; a bound socket without an accept loop closes
immediately. Nonblocking accept and readiness waits of at most 100 ms permit
stop without closing a descriptor that another thread still uses. Startup and
accept-loop callback exceptions clean up the listener and join the task queue.
An embedding runtime must still keep the server alive until listen returns.

With ownership enabled, the private virtual processor is `process_socket`; it must not close
the socket. Custom overrides of the old private `process_and_close_socket`
need updating for an owned build. This is intentional: retaining an override that closes a raw
descriptor would invalidate the ownership guarantee. Public handlers and client
APIs are unchanged. Custom task queues must finish/join all executing work in
`shutdown()` and must not throw from that cleanup.

The hooks do not implement application request admission, a connection registry,
a grace deadline, callback cancellation, or restart of retained application work.
The embedding service owns those policies. Socket interruption cannot stop an
arbitrary C++ callback. Fresh server instances after all network workers join
are the intended embedding restart pattern.

For exclusive binding beside another server, set POSIX `SO_REUSEADDR=1` and
`SO_REUSEPORT=0`. On Windows use `SO_EXCLUSIVEADDRUSE=1` instead: Windows
`SO_REUSEADDR` permits binding an occupied port and does not give the POSIX
contract. The lifecycle fixtures check an occupied port is rejected.

Capability macros are `CPPHTTPLIB_SERVER_CONNECTION_SUPPORT`,
`CPPHTTPLIB_SIGPIPE_POLICY_SUPPORT`, and `CPPHTTPLIB_OWNED_LISTENER_SUPPORT` (1).
All translation units of a compiled library must use consistent definitions;
the Orocos HTTP integration will consume the patched header privately.

Build the behavioral checks with:

```sh
cmake -S test/owned-connections -B build-owned -DCMAKE_BUILD_TYPE=Debug
cmake --build build-owned --parallel 2
ctest --test-dir build-owned --output-on-failure --parallel 2
```

The tests generate their own temporary TLS credentials in the build directory.
They cover queued disposal, rejection, active I/O and TLS handshake interruption,
held callbacks, graceful responses, startup exceptions, bind/TLS failures, raw
request targets, restart, SIGPIPE policy, and default/no-exceptions compatibility.
The POSIX listener test deliberately reuses the exact closed descriptor for an
unrelated socket pair. Raw-target tests prove origin-server byte preservation;
browser and reverse-proxy name normalization remains an integration concern.
