#include "httplib.h"

#include <future>
#include <memory>
#include <thread>

int main() {
#ifndef _WIN32
  signal(SIGPIPE, SIG_DFL);
#endif
  std::unique_ptr<httplib::Server> server;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  server.reset(new httplib::SSLServer("test.crt", "test.key"));
#else
  server.reset(new httplib::Server);
#endif
  if (!server->is_valid()) { return 1; }
#ifndef _WIN32
  struct sigaction disposition{};
  if (sigaction(SIGPIPE, nullptr, &disposition) ||
      disposition.sa_handler != SIG_IGN) {
    return 2;
  }
#endif
  server->new_task_queue = [] { return new httplib::ThreadPool(1, 1, 2); };
  server->Get("/health",
              [](const httplib::Request &, httplib::Response &response) {
                response.set_content("ready", "text/plain");
              });
  const int port = server->bind_to_any_port("127.0.0.1");
  if (port <= 0) { return 3; }
  std::promise<void> ready;
  server->set_start_handler([&] { ready.set_value(); });
  bool listen_ok = false;
  std::thread listener([&] { listen_ok = server->listen_after_bind(); });
  ready.get_future().get();
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  httplib::Client client("https://127.0.0.1:" + std::to_string(port));
  client.set_ca_cert_path("test.crt");
#else
  httplib::Client client("127.0.0.1", port);
#endif
  auto response = client.Get("/health");
  server->stop();
  listener.join();
  return listen_ok && response && response->status == 200 &&
                 response->body == "ready"
             ? 0
             : 4;
}
