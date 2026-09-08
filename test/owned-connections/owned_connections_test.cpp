#include "httplib.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <csignal>
#include <pthread.h>
#endif

#if CPPHTTPLIB_SERVER_CONNECTION_SUPPORT != 1 ||                               \
    CPPHTTPLIB_SIGPIPE_POLICY_SUPPORT != 1
#error The HTTP service requires the owned-connection and SIGPIPE policy hooks
#endif
#if CPPHTTPLIB_OWNED_LISTENER_SUPPORT != 1
#error The HTTP service requires owned listener cleanup
#endif

namespace {
using Clock = std::chrono::steady_clock;
using Connection = std::shared_ptr<httplib::ServerConnection>;

void check(bool value, const char *message) {
  if (!value) { throw std::runtime_error(message); }
}

void block_sigpipe() {
#ifndef _WIN32
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGPIPE);
  check(pthread_sigmask(SIG_BLOCK, &mask, nullptr) == 0, "block SIGPIPE");
#endif
}

class RawClient {
public:
  explicit RawClient(int port) : sock_(::socket(AF_INET, SOCK_STREAM, 0)) {
    check(sock_ != INVALID_SOCKET, "create socket");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(static_cast<uint16_t>(port));
    if (::connect(sock_, reinterpret_cast<sockaddr *>(&address),
                  sizeof(address))) {
      httplib::detail::close_socket(sock_);
      throw std::runtime_error("connect socket");
    }
    httplib::detail::set_socket_opt_time(sock_, SOL_SOCKET, SO_RCVTIMEO, 2, 0);
  }
  ~RawClient() {
    httplib::detail::shutdown_socket(sock_);
    httplib::detail::close_socket(sock_);
  }
  void send(const std::string &text) {
    check(httplib::detail::send_socket(sock_, text.data(), text.size(),
                                       CPPHTTPLIB_SEND_FLAGS) > 0,
          "send socket");
  }
  bool is_disconnected() {
    char byte;
    const auto ready = httplib::detail::select_read(sock_, 2, 0);
    return ready > 0 && httplib::detail::read_socket(sock_, &byte, 1, 0) <= 0;
  }
  std::string receive() {
    std::string result;
    char bytes[4096];
    for (;;) {
      auto count = httplib::detail::read_socket(sock_, bytes, sizeof(bytes), 0);
      if (count <= 0) { break; }
      result.append(bytes, static_cast<size_t>(count));
    }
    return result;
  }
  RawClient(const RawClient &) = delete;
  RawClient &operator=(const RawClient &) = delete;

private:
  socket_t sock_;
};

// Controlled scheduling proves queued sockets are never processed, including
// TLS handshakes. It avoids guessing whether a real worker has dequeued a job.
class ControlledQueue : public httplib::TaskQueue {
public:
  explicit ControlledQueue(bool reject = false) : reject_(reject) {}
  bool enqueue(std::function<void()> task) override {
    std::lock_guard<std::mutex> lock(mutex_);
    ++offered_;
    if (!reject_) { jobs_.push_back(std::move(task)); }
    ready_.notify_all();
    return !reject_;
  }
  void shutdown() override {
    std::lock_guard<std::mutex> lock(mutex_);
    jobs_.clear();
  }
  void wait_for_offers(size_t count) {
    std::unique_lock<std::mutex> lock(mutex_);
    check(ready_.wait_for(lock, std::chrono::seconds(3),
                          [&] { return offered_ >= count; }),
          "queue offer timeout");
  }
  void execute() {
    std::vector<std::function<void()>> jobs;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      jobs.swap(jobs_);
    }
    for (auto &job : jobs) {
      job();
    }
  }

private:
  bool reject_;
  std::mutex mutex_;
  std::condition_variable ready_;
  size_t offered_ = 0;
  std::vector<std::function<void()>> jobs_;
};

struct Connections {
  void accepted(Connection connection) {
    std::lock_guard<std::mutex> lock(mutex);
    if (cancelling) { connection->cancel(); }
    values.push_back(std::move(connection));
    ready.notify_all();
  }
  Connection at(size_t index) {
    std::unique_lock<std::mutex> lock(mutex);
    check(ready.wait_for(lock, std::chrono::seconds(3),
                         [&] { return values.size() > index; }),
          "accept timeout");
    return values.at(index);
  }
  void cancel_all() {
    std::lock_guard<std::mutex> lock(mutex);
    cancelling = true;
    for (const auto &connection : values) {
      connection->cancel();
    }
  }
  std::mutex mutex;
  std::condition_variable ready;
  std::vector<Connection> values;
  bool cancelling = false;
};

// Signal masking precedes construction, and remains in force until the TLS
// server and all workers have been destroyed. The caller's mask is untouched.
struct RunningServer {
  explicit RunningServer(bool tls, bool controlled = false, bool reject = false,
                         bool throw_hook = false, bool throw_request = false,
                         httplib::Server::Handler handler = {},
                         int bind_port = 0) {
    std::promise<int> ready;
    auto result = ready.get_future();
    listener = std::thread([this, tls, controlled, reject, throw_hook,
                            throw_request, handler, bind_port, &ready] {
      try {
        block_sigpipe();
        std::unique_ptr<httplib::Server> owned;
        if (tls) {
          owned.reset(new httplib::SSLServer("test.crt", "test.key"));
        } else {
          owned.reset(new httplib::Server);
        }
        server = owned.get();
        check(server->is_valid(), "server TLS configuration");
        server->set_socket_options([](socket_t socket) {
#ifdef _WIN32
          httplib::set_socket_opt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1);
#else
          httplib::set_socket_opt(socket, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef SO_REUSEPORT
          httplib::set_socket_opt(socket, SOL_SOCKET, SO_REUSEPORT, 0);
#endif
#endif
        });
        server->set_read_timeout(30);
        server->set_write_timeout(30);
        server->set_connection_handler([this, throw_hook](Connection value) {
          connections.accepted(std::move(value));
          if (throw_hook) { throw std::runtime_error("hook failure"); }
        });
        server->Get("/.*", [this, throw_request,
                            handler](const httplib::Request &request,
                                     httplib::Response &response) {
          requests.fetch_add(1);
          if (throw_request) { throw std::runtime_error("request failure"); }
          if (handler) {
            handler(request, response);
            return;
          }
          response.set_content(request.target, "text/plain");
        });
        const int bound =
            bind_port == 0
                ? server->bind_to_any_port("127.0.0.1")
                : (server->bind_to_port("127.0.0.1", bind_port) ? bind_port
                                                                : -1);
        check(bound > 0, "bind server");
        server->new_task_queue = [this, controlled, reject, bound,
                                  &ready]() -> httplib::TaskQueue * {
          httplib::TaskQueue *value;
          if (controlled) {
            queue = new ControlledQueue(reject);
            value = queue;
          } else {
            value = new httplib::ThreadPool(2, 2, 4);
          }
          ready.set_value(bound);
          return value;
        };
        check(server->listen_after_bind(), "listen loop");
        // Keep server storage alive until the stop caller has returned from
        // stop() and finished cancelling connection handles.
        std::unique_lock<std::mutex> lock(cleanup_mutex);
        cleanup_ready.wait(lock, [this] { return cleanup_permitted; });
      } catch (...) {
        failure = std::current_exception();
        try {
          ready.set_exception(failure);
        } catch (...) {}
      }
    });
    try {
      port = result.get();
    } catch (...) {
      listener.join();
      throw;
    }
  }
  ~RunningServer() {
    if (listener.joinable()) {
      server->stop();
      connections.cancel_all();
      permit_cleanup();
      listener.join();
    }
  }
  void stop() {
    server->stop();
    connections.cancel_all();
    permit_cleanup();
    listener.join();
    if (failure) { std::rethrow_exception(failure); }
  }
  std::atomic<int> requests{0};
  Connections connections;
  ControlledQueue *queue = nullptr;
  httplib::Server *server = nullptr;
  int port = 0;
  std::thread listener;
  std::exception_ptr failure;

private:
  void permit_cleanup() {
    std::lock_guard<std::mutex> lock(cleanup_mutex);
    cleanup_permitted = true;
    cleanup_ready.notify_all();
  }
  std::mutex cleanup_mutex;
  std::condition_variable cleanup_ready;
  bool cleanup_permitted = false;
};

void queued(bool tls, bool discarded, bool rejected) {
  RunningServer runtime(tls, true, rejected);
  RawClient client(runtime.port);
  if (!tls) { client.send("GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n"); }
  auto connection = runtime.connections.at(0);
  runtime.queue->wait_for_offers(1);
  if (discarded) {
    runtime.queue->shutdown();
  } else if (!rejected) {
    connection->cancel();
    runtime.queue->execute();
  }
  check(client.is_disconnected(), "queued/rejected connection stayed open");
  check(connection->is_closed(),
        "retained handle kept a discarded socket open");
  check(runtime.requests == 0, "discarded request was dispatched");
  runtime.stop();
}

void interrupted(bool tls) {
  RunningServer runtime(tls);
  RawClient client(runtime.port);
  if (!tls) { client.send("GET /health HTTP/1.1\r\nHost:"); }
  auto connection = runtime.connections.at(0);
  // Wait for actual worker ownership. This proves interruption of an active
  // partial HTTP read or stalled TLS handshake, not only a queued discard.
  const auto admission_deadline = Clock::now() + std::chrono::seconds(3);
  while (!connection->is_active() && Clock::now() < admission_deadline) {
    std::this_thread::yield();
  }
  check(connection->is_active(), "worker admission timeout");
  const auto start = Clock::now();
  runtime.stop();
  check(Clock::now() - start < std::chrono::seconds(2),
        "interruption waited for I/O timeout");
  check(connection->is_closed(), "interrupted socket not finalized");
  check(client.is_disconnected(), "interrupted peer still connected");
}

void restart(bool tls) {
  std::vector<Connection> old_handles;
  std::vector<std::unique_ptr<httplib::Client>> old_clients;
  int bind_port = 0;
  // Fresh server generations are the intended HTTP-service restart policy.
  for (int round = 0; round < 3; ++round) {
    RunningServer runtime(tls, false, false, false, false, {}, bind_port);
    bind_port = runtime.port;
    std::unique_ptr<httplib::Client> client(new httplib::Client(
        std::string(tls ? "https://127.0.0.1:" : "http://127.0.0.1:") +
        std::to_string(runtime.port)));
    if (tls) { client->set_ca_cert_path("test.crt"); }
    client->set_keep_alive(true);
    auto response = client->Get("/health");
    check(response && response->status == 200, "initial HTTP(S) request");
    old_handles.push_back(runtime.connections.at(0));
    // Old handles can no longer operate on descriptors reused by this server.
    for (size_t index = 0; index + 1 < old_handles.size(); ++index) {
      check(old_handles[index]->is_closed(), "old handle still open");
      old_handles[index]->cancel();
    }
    response = client->Get("/health");
    check(response && response->status == 200,
          "old cancellation damaged new connection");
    runtime.stop();
    // An idle browser may retain its half-closed peer socket across restart.
    // Rebind the same endpoint, without depending on that browser's cleanup.
    old_clients.push_back(std::move(client));
  }
}

void raw_target() {
  RunningServer runtime(false);
  for (const auto *target :
       {"/health?name=motion%2Fraw%252F", "/api/services/motion%2Fraw",
        "/api/services/motion%252Fraw", "/api/services/%E6%9C%BA%E5%99%A8",
        "/api/services/a+b", "/api/services/%2e", "/api/services/..",
        "/api/services//properties"}) {
    RawClient client(runtime.port);
    client.send(std::string("GET ") + target +
                " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    check(client.receive().find(target) != std::string::npos,
          "raw request target changed");
  }
  runtime.stop();
}

class InspectableServer : public httplib::Server {
public:
  socket_t listener_socket() const { return svr_sock_.load(); }
};

bool socket_exists(socket_t sock) {
  int type = 0;
  socklen_t length = sizeof(type);
  return getsockopt(sock, SOL_SOCKET, SO_TYPE, reinterpret_cast<char *>(&type),
                    &length) == 0;
}

void listener_ownership() {
  InspectableServer server;
  server.new_task_queue = [] { return new ControlledQueue; };
  check(server.bind_to_any_port("127.0.0.1") > 0, "bind owned listener");
  const auto descriptor = server.listener_socket();
  std::promise<void> entered, release;
  auto held = release.get_future();
  server.set_start_handler([&] {
    entered.set_value();
    held.wait();
  });
  auto running = std::async(std::launch::async, [&] {
    block_sigpipe();
    return server.listen_after_bind();
  });
  entered.get_future().get();
  server.stop();
  const bool retained = socket_exists(descriptor);
  release.set_value();
  check(running.get(), "owned listener exit");
  check(retained, "stop closed listener still owned by accept loop");
  check(!socket_exists(descriptor), "accept exit leaked listener");

#ifndef _WIN32
  // Force reuse of exactly the closed listener descriptor. A stale stop must
  // not shut down this unrelated subsystem's socket (for example OPC UA).
  int pair[2];
  check(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "reuse socket pair");
  if (pair[1] == descriptor) { std::swap(pair[0], pair[1]); }
  if (pair[0] != descriptor) {
    check(dup2(pair[0], descriptor) == descriptor, "force descriptor reuse");
    close(pair[0]);
    pair[0] = descriptor;
  }
  server.stop();
  const char value = 'x';
  char received = 0;
  const auto sent = send(pair[0], &value, 1, MSG_NOSIGNAL);
  const auto count = sent == 1 ? recv(pair[1], &received, 1, 0) : -1;
  close(pair[0]);
  close(pair[1]);
  check(count == 1 && received == value,
        "stale stop damaged reused descriptor");
#endif

  check(server.bind_to_any_port("127.0.0.1") > 0, "rebind stopped server");
  const auto rebound = server.listener_socket();
  check(server.bind_to_any_port("127.0.0.1") < 0, "duplicate bind accepted");
  server.stop();
  check(!socket_exists(rebound), "stop before listen leaked descriptor");
  check(!server.listen_after_bind(), "listen after stop succeeded");
  server.wait_until_ready();
}

void startup_failure(bool queue_failure) {
  InspectableServer server;
  const auto port = server.bind_to_any_port("127.0.0.1");
  check(port > 0, "bind startup failure fixture");
  const auto descriptor = server.listener_socket();
  server.new_task_queue = [queue_failure]() -> httplib::TaskQueue * {
    if (queue_failure) { throw std::runtime_error("queue allocation failure"); }
    return new ControlledQueue;
  };
  server.set_start_handler([] { throw std::runtime_error("startup failure"); });
  check(!server.listen_after_bind(), "startup exception escaped containment");
  check(!server.is_running(), "startup exception left server running");
  check(!socket_exists(descriptor), "startup exception leaked listener");
  server.wait_until_ready();
  server.stop();
}

void bind_callback_failure() {
  InspectableServer server;
  socket_t captured = INVALID_SOCKET;
  server.set_socket_options([&](socket_t socket) {
    captured = socket;
    throw std::runtime_error("socket options failure");
  });
  bool threw = false;
  try {
    server.bind_to_any_port("127.0.0.1");
  } catch (const std::runtime_error &) { threw = true; }
  check(threw && captured != INVALID_SOCKET,
        "socket options callback did not run");
  check(!socket_exists(captured), "throwing socket options leaked descriptor");
  server.set_socket_options([&](socket_t socket) {
    captured = socket;
    server.stop();
  });
  check(server.bind_to_any_port("127.0.0.1") < 0,
        "stop during bind was ignored");
  check(!socket_exists(captured), "stop during bind leaked descriptor");
  server.stop();
}

void configuration_failures() {
  RunningServer runtime(false);
  httplib::Server conflicting;
  conflicting.set_socket_options([](socket_t socket) {
#ifdef _WIN32
    httplib::set_socket_opt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1);
#else
    httplib::set_socket_opt(socket, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef SO_REUSEPORT
    httplib::set_socket_opt(socket, SOL_SOCKET, SO_REUSEPORT, 0);
#endif
#endif
  });
  check(!conflicting.bind_to_port("127.0.0.1", runtime.port),
        "bind conflict succeeded");
  conflicting.stop();
  httplib::SSLServer invalid("missing-certificate.pem", "missing-key.pem");
  check(!invalid.is_valid(), "invalid TLS configuration accepted");
  check(invalid.bind_to_any_port("127.0.0.1") < 0,
        "invalid TLS listener bound");
  invalid.stop();
  httplib::Client client("127.0.0.1", runtime.port);
  auto response = client.Get("/health");
  check(response && response->status == 200,
        "startup failure affected other server");
  runtime.stop();
}

// Hold an actual request callback while network shutdown progresses. The
// callback is explicitly released in every path; socket interruption is not
// permission to destroy a callback's server storage or terminate its thread.
void active_response(bool tls, bool broken_peer, bool interrupt) {
  std::promise<void> entered, release;
  auto released = release.get_future().share();
  RunningServer runtime(
      tls, false, false, false, false,
      [&](const httplib::Request &, httplib::Response &response) {
        entered.set_value();
        released.wait();
        response.set_content(std::string(65536, 'x'), "text/plain");
      });
  httplib::Client client(
      std::string(tls ? "https://127.0.0.1:" : "http://127.0.0.1:") +
      std::to_string(runtime.port));
  if (tls) { client.set_ca_cert_path("test.crt"); }
  auto request = std::async(std::launch::async, [&] {
    block_sigpipe();
    return client.Get("/held");
  });
  entered.get_future().get();
  auto connection = runtime.connections.at(0);
  runtime.server->stop();
  if (broken_peer) {
    client.stop();
    request.wait();
  }
  if (interrupt) { runtime.connections.cancel_all(); }
  const bool retained = connection->is_active() && !connection->is_closed();
  release.set_value();
  auto response = request.get();
  runtime.stop();
  check(retained, "stop finalized socket while callback was held");
  check(connection->is_closed(), "callback completion leaked socket");
  if (!broken_peer && !interrupt) {
    check(response && response->status == 200 && response->body.size() == 65536,
          "graceful stop lost active response");
  }
}

void signal_policy() {
#ifndef _WIN32
  struct sigaction original{}, probe{}, after{};
  check(sigaction(SIGPIPE, nullptr, &original) == 0,
        "read SIGPIPE disposition");
  probe.sa_handler = SIG_DFL;
  sigemptyset(&probe.sa_mask);
  check(sigaction(SIGPIPE, &probe, nullptr) == 0,
        "install SIGPIPE test disposition");
  sigset_t before_mask{}, after_mask{};
  pthread_sigmask(SIG_SETMASK, nullptr, &before_mask);
  {
    RunningServer runtime(false);
    runtime.stop();
    RunningServer tls_runtime(true);
    tls_runtime.stop();
    active_response(false, true, false);
    active_response(true, true, false);
  }
  check(sigaction(SIGPIPE, nullptr, &after) == 0,
        "read final SIGPIPE disposition");
  pthread_sigmask(SIG_SETMASK, nullptr, &after_mask);
  sigaction(SIGPIPE, &original, nullptr);
  check(after.sa_handler == SIG_DFL, "server changed SIGPIPE disposition");
  check(sigismember(&before_mask, SIGPIPE) == sigismember(&after_mask, SIGPIPE),
        "server changed caller signal mask");
#endif
}
} // namespace

int main(int argc, char **argv) {
  try {
    check(argc == 2, "expected test case");
    const std::string name = argv[1];
    const bool tls = name.find("_tls") != std::string::npos;
    if (name.find("queue_") == 0) {
      queued(tls, false, false);
    } else if (name.find("reject_") == 0) {
      queued(tls, false, true);
    } else if (name.find("discarded_") == 0) {
      queued(tls, true, false);
    } else if (name.find("interrupted_") == 0) {
      interrupted(tls);
    } else if (name.find("restart_") == 0) {
      restart(tls);
    } else if (name == "hook_exception") {
      RunningServer runtime(false, false, false, true);
      RawClient client(runtime.port);
      check(client.is_disconnected(), "throwing hook leaked socket");
      runtime.stop();
    } else if (name == "request_exception") {
      RunningServer runtime(false, false, false, false, true);
      httplib::Client client("127.0.0.1", runtime.port);
      auto response = client.Get("/health");
      check(response && response->status == 500, "request exception response");
      runtime.stop();
    } else if (name == "raw_target") {
      raw_target();
    } else if (name == "signal_policy") {
      signal_policy();
    } else if (name == "listener_ownership") {
      listener_ownership();
    } else if (name == "start_exception") {
      startup_failure(false);
    } else if (name == "queue_exception") {
      startup_failure(true);
    } else if (name == "bind_callback_failure") {
      bind_callback_failure();
    } else if (name == "configuration_failures") {
      configuration_failures();
    } else if (name.find("grace_") == 0) {
      active_response(tls, false, false);
    } else if (name.find("held_") == 0) {
      active_response(tls, false, true);
    } else {
      throw std::runtime_error("unknown case");
    }
    std::cout << "PASS " << name << '\n';
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "FAIL: " << error.what() << '\n';
    return 1;
  }
}
