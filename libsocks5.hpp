// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.
#ifndef MEASUREMENT_KIT_LIBSOCKS5_HPP
#define MEASUREMENT_KIT_LIBSOCKS5_HPP

/// \file libsocks5.hpp
///
/// \brief Public header of measurement-kit/libsocks5. The typical usage
/// entails creating a Client instance, possibly with specific Settings, and
/// then calling its run() method to start serving clients.

#ifndef _WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <assert.h>
#ifndef _WIN32
#include <fcntl.h>
#endif
#include <limits.h>
#ifndef _WIN32
#include <netdb.h>
#include <poll.h>
#endif
#include <stddef.h>
#include <stdint.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifdef LIBSOCKS5_HAVE_GETDNS
#include <getdns/getdns.h>
#endif  // LIBSOCKS5_HAVE_GETDNS

/// Contains measurement_kit code.
namespace measurement_kit {

/// Contains measurement-kit/libsocks5 code.
namespace libsocks5 {

/// Type containing a version number.
using Version = unsigned int;

/// Major API version number of measurement-kit/libndt.
constexpr Version version_major = Version{0};

/// Minor API version number of measurement-kit/libndt.
constexpr Version version_minor = Version{0};

/// Patch API version number of measurement-kit/libndt.
constexpr Version version_patch = Version{0};

/// Options that you can set as binary flags.
using Options = unsigned int;

/// Use getdns to resolve hostnames rather than getaddrinfo(). For this to work
/// getdns needs to be installed and the `LIBSOCKS5_HAVE_GETDNS` preprocessor
/// flag also must be set when including this header.
constexpr Options option_getdns = Options{1 << 0};

/// In case you are using a DNS engine such as getdns and name resolution fails
/// fallback to using getaddrinfo() to resolve the domain.
constexpr Options option_dns_fallback = Options{1 << 1};

/// Trace connect(), send(), recv(), and close() calls that occur on the
/// socket that is directly connected to the remote host.
constexpr Options option_trace = Options{1 << 2};

/// How much verbose must the library be.
using Verbosity = unsigned int;

/// Do not emit any log message.
constexpr Verbosity verbosity_quiet = Verbosity{0};

/// Emit only warning messages.
constexpr Verbosity verbosity_warning = Verbosity{1};

/// Emit warning and informational messages.
constexpr Verbosity verbosity_info = Verbosity{2};

/// Emit all log messages.
constexpr Verbosity verbosity_debug = Verbosity{3};

/// socks5 server settings. If you do not customize the settings when creating
/// a Server, the defaults listed below will be used instead.
class Settings {
 public:
  /// Hint on number of threads to use. The actual number will be three times
  /// the number you configure here (but most threads will be inactive). The
  /// default value is tailored to OONI typical usage.
  uint16_t parallelism = 7;

  /// Port where to listen for socks5 connections.
  uint16_t port = 6789;

  /// Timeout for I/O operations. The default value is tailored to generic
  /// usage but you may want to make it smaller when using a browser.
  uint16_t timeout_millisecond = 15000;

  /// Options that you can set as binary flags.
  Options options = Options{0};

  /// Verbosity of the server. By default we're super quiet.
  Verbosity verbosity = verbosity_quiet;
};

/// Socks5 server.
class Server {
 public:
  /* Implementation note: this is not meant to be a fancy low-overhead
     feature complete socks5 server implementation. Rather, the main
     objective is to keep the code simple such that we can easily apply
     changes when our measurement requirements change. Hence, the choice
     of using threading rather than asynchronous API, e.g. libuv.

     The main use case of this library is to act as a middle man between
     OONI's WebConnectivity and the network, to be able to capture
     interesting stuff, like network errors etc. It can actually also
     be used with any HTTP client that speaks socks5h (i.e. the one
     where the socks server performs DNS name resolution), mainly
     for fun and experimentation. One such client is Mozilla Firefox. */

  /// Constructor with default settings.
  Server() noexcept;

  /// Constructor with explicit settings.
  explicit Server(Settings settings) noexcept;

  /// Deleted copy constructor.
  Server(const Server &) noexcept = delete;

  /// Deleted copy assignment operator.
  Server &operator=(const Server &) noexcept = delete;

  /// Deleted move constructor.
  Server(Server &&) noexcept = delete;

  /// Deleted move assignment operator.
  Server &operator=(Server &&) noexcept = delete;

  /// Destroys allocated resources.
  virtual ~Server() noexcept;

  /// Runs in the current thread.
  bool run() noexcept;

  /// Interrupts a running socks5 server
  void interrupt() noexcept;

  /// Classify system error value mapping it into a string. The strings are
  /// the same used by the C++ >= 11 standard library inside of the std::errc
  /// enum class. @see <https://en.cppreference.com/w/cpp/error/errc> for a
  /// mapping between such values and POSIX error codes. @remark You can use
  /// this method to map any _negative_ return value in the callbacks that are
  /// called when tracing is enabled via Settings. Do not pass zero or positive
  /// values; this function does not know their semantics, which depends on the
  /// specific API. Zero or positive values will map to "io_error".
  std::string errno_to_string(int64_t return_value) noexcept;

  /// Called after connect when trace is enabled. Tracing will only trace
  /// events occurring on the socket connected to the remote host.
  virtual void on_connect(int64_t sock, const sockaddr *sa, socklen_t salen,
                          int return_value) noexcept;

  /// Called after send when trace is enabled. Tracing will only trace
  /// events occurring on the socket connected to the remote host.
  virtual void on_send(int64_t sock, const char *buf, size_t total,
                       int64_t return_value) noexcept;

  /// Called after recv when trace is enabled. Tracing will only trace
  /// events occurring on the socket connected to the remote host.
  virtual void on_recv(int64_t sock, char *buf, size_t maxlen,
                       int64_t return_value) noexcept;

  /// Called after close when trace is enabled. Tracing will only trace
  /// events occurring on the socket connected to the remote host.
  virtual void on_closesocket(int64_t sock, int return_value) noexcept;

#ifdef LIBSOCKS5_HAVE_GETDNS
  /// Called in case of getdns success. You do not own the @p reply
  /// argument, which will be deleted right after this call.
  virtual void on_getdns_success(getdns_dict *reply) noexcept;
#endif  // LIBSOCKS5_HAVE_GETDNS

  /// Called only once if and only if we identify a SSL >= 3 record containing
  /// the certificates. The buffer that you're provided with contains the
  /// full TLS record that contains the certificate. We currently use a fixed
  /// size buffer for sniffing TLS. However the buffer should be big enough
  /// that in most cases the certificates won't be truncated. @remark in case
  /// of truncation this method will not be called.
  virtual void on_tls_handshake_cert(std::string record) noexcept;

  /// Handles a warning log message.
  virtual void on_warning(std::string message) noexcept;

  /// Handles a info log message.
  virtual void on_info(std::string message) noexcept;

  /// Handles a debug log message.
  virtual void on_debug(std::string message) noexcept;

  // You probably don't want to override these methods unless you are into
  // heavy customization or you're writing regress tests.
 protected:
#ifdef LIBSOCKS5_HAVE_GETDNS
  // Like so_resolve_hostname() but using the getdns backend.
  virtual int so_resolve_hostname_getdns(
      std::string hostname, std::vector<std::string> *addresses) noexcept;
#endif  // LIBSOCKS5_HAVE_GETDNS

  // Resolve @p hostname into a list of @p addresses. @return 0 on success.
  virtual int so_resolve_hostname(std::string hostname,
                                  std::vector<std::string> *addresses) noexcept;

  // Overridable wrapper for getaddrinfo(). @return 0 on success.
  virtual int so_getaddrinfo(const char *hostname, const char *servname,
                             const addrinfo *hints, addrinfo **rp) noexcept;

  // Overridable wrapper for freeaddrinfo().
  virtual void so_freeaddrinfo(addrinfo *rp) noexcept;

  // Portable, overridable socket() wrapper. @return -1 on failure.
  virtual int64_t so_socket(int domain, int type, int protocol) noexcept;

  // Handy helper to set common options on a new socket. @return 0 on success.
  virtual int so_setoptions_common_quick(int64_t fd) noexcept;

  // Overridable wrapper for closesocket(). @return 0 on success.
  virtual int so_closesocket(int64_t fd) noexcept;

  // Overridable wrapper for bind(). @return 0 on success.
  virtual int so_bind(int64_t fd, const sockaddr *sa,
                      socklen_t len) noexcept;

  // Overridable wrapper for connect(). @return 0 on success.
  virtual int so_connect(int64_t fd, const sockaddr *sa,
                         socklen_t len) noexcept;

  // Overridable wrapper for poll(). @return 0 on success, negative on error. A
  // timeout is always reported as an error. The number of active sockets is not
  // returned to the caller by this implementation. Zero means that at least a
  // socket has some poll flags that are set. Note that some flags may indicate
  // that the socket is e.g. invalid (POLLNVAL), closed (POLLHUP).
  virtual int so_poll(pollfd *fds, uint64_t nfds, int milli) noexcept;

  // Wait for @p fd to change state. @p flags should be POLLIN or POLLOUT or
  // other macros accepted by the poll() syscall. @return 0 on success. If the
  // descriptor is invalid, an error code is returned.
  virtual int so_wait_flags(int64_t fd, short flags, int milli) noexcept;

  // Wait until @p is writeable. @return 0 on success. @see so_wait_flags() for
  // a discussion of the handling of invalid descriptors.
  virtual int so_wait_writeable(int64_t fd, int milli) noexcept;

  // Wait until @p is readable. @return 0 on success. @see so_wait_flags() for
  // a discussion of the handling of invalid descriptors.
  virtual int so_wait_readable(int64_t fd, int milli) noexcept;

  // Overridable wrapper for getsockopt(). @return 0 on success.
  virtual int so_getsockopt(int64_t fd, int level, int option_name,
                            char *option_value, socklen_t *option_len) noexcept;

  // Overridable wrapper for setsockopt(). @return 0 on success.
  virtual int so_setsockopt(int64_t fd, int level, int option_name,
                            char *option_value, socklen_t option_len) noexcept;

  // Nonblocking recv. @return size on success, zero on EOF, negative on error.
  virtual int64_t so_recv_nonblock(int64_t fd, char *p, uint64_t n) noexcept;

  // Blocking recv. @return size on success, zero on EOF, negative on error.
  virtual int64_t so_recv(int64_t fd, char *p, uint64_t n) noexcept;

  // Exact recv. @return size on success, zero on EOF, negative on error.
  virtual int64_t so_recvn(int64_t fd, char *p, uint64_t n) noexcept;

  // Nonblocking send. @return size on success, zero on EOF, negative on error.
  virtual int64_t so_send_nonblock(int64_t fd, const char *p,
                                   uint64_t n) noexcept;

  // Blocking send. @return size on success, zero on EOF, negative on error.
  virtual int64_t so_send(int64_t fd, const char *p, uint64_t n) noexcept;

  // Exact send. @return size on success, zero on EOF, negative on error.
  virtual int64_t so_sendn(int64_t fd, const char *p, uint64_t n) noexcept;

  // Wrapper for accept(). @return -1 on failure.
  virtual int64_t so_accept(int64_t fd, sockaddr *n, socklen_t *ln) noexcept;

 private:
  // Worker method that actually implements the socks5 protocol.
  int socks5h_dispatch(int64_t clientfd) noexcept;

  // Checks for buffered data in search for initial TLS handshake.
  void decode_tls(const std::string &data) noexcept;

  // Opaque implementation.
  class Impl;

  // Unique pointer to the opaque implementation.
  std::unique_ptr<Impl> impl;
};

// Define this macro if you need to include this file in multiple translation
// units such that symbols will not be duplicated.
#ifndef LIBSOCKS5_NO_INLINE_IMPL

#define EMIT_LOG(level, stmts)                           \
  do {                                                   \
    if (impl->settings.verbosity >= verbosity_##level) { \
      std::stringstream ss;                              \
      ss << stmts;                                       \
      auto s = ss.str();                                 \
      on_##level(std::move(s));                          \
    }                                                    \
  } while (0)

#define EMIT_WARNING(stmts) EMIT_LOG(warning, stmts)
#define EMIT_INFO(stmts) EMIT_LOG(info, stmts)
#define EMIT_DEBUG(stmts) EMIT_LOG(debug, stmts)

class Server::Impl {
 public:
  std::condition_variable cond;
  std::atomic_bool interrupted{false};
  std::mutex mutex;
  std::deque<uint64_t> queue;
  std::atomic_bool running{false};
  Settings settings;
};

// Public API
// ``````````

Server::Server() noexcept : Server{Settings{}} {}

Server::Server(Settings settings) noexcept {
  impl.reset(new Server::Impl);
  std::swap(impl->settings, settings);
}

Server::~Server() noexcept {}

bool Server::run() noexcept {
  {
    std::unique_lock<std::mutex> _{impl->mutex};
    if (impl->running) {
      return false;
    }
    impl->running = true;
  }
  int64_t listenfd = -1;
  {
    listenfd = so_socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd == -1) {
      EMIT_WARNING("run: cannot create socket");
      return false;
    }
    EMIT_DEBUG("run: socket created");
    {
      int on = -1;
      socklen_t olen = sizeof(on);
      if (so_setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
                        (char *)&on, olen) != 0) {
        EMIT_WARNING("run: cannot set SO_REUSEADDR");
        (void)so_closesocket(listenfd);
        return false;
      }
    }
    EMIT_DEBUG("run: set SO_REUSEADDR");
    {
      sockaddr_in sin{};
      sin.sin_family = AF_INET;
      sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      sin.sin_port = htons(impl->settings.port);
      if (so_bind(listenfd, (sockaddr *)&sin, sizeof(sin)) != 0) {
        EMIT_WARNING("run: bind() failed");
        (void)so_closesocket(listenfd);
        return false;
      }
    }
    EMIT_DEBUG("run: bound to endpoint");
    // We may actually end up adding more options than required. Not an issue.
    if (so_setoptions_common_quick(listenfd) != 0) {
      EMIT_WARNING("run: so_setoptions_common_quick() failed");
      (void)so_closesocket(listenfd);
      return false;
    }
    EMIT_DEBUG("run: set additional options");
    constexpr auto backlog = 10;
    if (::listen(listenfd, backlog) != 0) {
      EMIT_WARNING("run: listen() failed");
      (void)so_closesocket(listenfd);
      return false;
    }
    EMIT_DEBUG("run: listening on socket " << listenfd);
  }
  if (impl->settings.parallelism <= 0) {
    EMIT_WARNING("run: invalid parallelism argument");
    return false;
  }
  std::atomic<uint64_t> active{impl->settings.parallelism};
  auto worker = [&active, this](uint64_t idx) noexcept {
    EMIT_DEBUG("thread " << idx << " started");
    for (;;) {
      int64_t clientfd = -1;
      {
        std::unique_lock<std::mutex> lock{impl->mutex};
        impl->cond.wait(lock, [this]() noexcept {
          return impl->interrupted || !impl->queue.empty();
        });
        if (impl->interrupted) break;
        clientfd = impl->queue.front();
        impl->queue.pop_front();
      }
      (void)socks5h_dispatch(clientfd);
      (void)so_closesocket(clientfd);
    }
    EMIT_DEBUG("thread " << idx << " stopped");
    active -= 1;
  };
  for (uint64_t i = 0; i < active; ++i) std::thread{worker, i}.detach();
  while (active > 0) {
    constexpr int timeout_millisec = 250000;
    auto err = 0;
    err = so_wait_readable(listenfd, timeout_millisec);
    if (err == -ETIMEDOUT) continue;
    if (err != 0) break;
    int64_t clientfd = so_accept(listenfd, nullptr, nullptr);
    if (clientfd == -1) continue;
    EMIT_DEBUG("accepted socket " << clientfd);
    {
      std::unique_lock<std::mutex> _{impl->mutex};
      if (impl->queue.size() > 0) {
        // Reasoning: rather than having the queue build up it's probably
        // best to kill the connections we cannot serve _pronto_.
        EMIT_DEBUG("closing socket " << clientfd << ": queue is building up");
        (void)so_closesocket(clientfd);
        continue;
      }
      EMIT_DEBUG("queued socket " << clientfd);
      impl->queue.push_back(clientfd);
    }
    impl->cond.notify_one();  // more efficient if unlocked
  }
  impl->interrupted = false;
  impl->running = false;
  (void)so_closesocket(listenfd);
  return true;
}

void Server::interrupt() noexcept {
  impl->interrupted = true;  // atomic
  impl->cond.notify_all();   // more efficient if unlocked
}

static std::string  //
sockaddr_to_string(const sockaddr *sa, socklen_t salen) noexcept {
  std::stringstream ss;
  ss << "sockaddr{";
  char buf[46];  // See <https://stackoverflow.com/a/1076755>
  if (salen == sizeof(sockaddr_in)) {
    ss << "\"";
    if (inet_ntop(AF_INET, sa, buf, sizeof(buf)) != nullptr) {
      ss << buf;
    }
    ss << "\", ";
    ss << std::to_string(ntohs(((sockaddr_in *)sa)->sin_port));
  } else if (salen == sizeof(sockaddr_in6)) {
    ss << "\", ";
    if (inet_ntop(AF_INET6, sa, buf, sizeof(buf)) != nullptr) {
      ss << buf;
    }
    ss << "\", ";
    ss << std::to_string(ntohs(((sockaddr_in6 *)sa)->sin6_port));
  } else {
    /* Nothing */
  }
  ss << "}";
  return ss.str();
}

static std::string buffer_to_string(const char *buf, uint64_t total) noexcept {
  std::stringstream ss;
  ss << "buffer[" << total << "]{ ";
  if (buf != nullptr) {
    constexpr uint64_t snap = 12;
    for (uint64_t i = 0; i < snap && i < total; ++i) {
      auto ch = (uint8_t)buf[i];
      if (ch < ' ' || ch > '~') {
        ss << std::setw(2) << std::setfill('0')
           << std::hex << (uint64_t)ch << " ";
      } else {
        ss << ch << " ";
      }
    }
    if (total > snap) ss << "... ";
  } else {
    ss << "null ";
  }
  ss << "}";
  return ss.str();
}

std::string Server::errno_to_string(int64_t return_value) noexcept {
  assert(return_value < 0);  // See the documentation
  // clang-format off
  // As you'll probably see below, we conflate several nonbocking status
  // codes into -EAGAIN. And anyway the user should not see -EAGAIN, so
  // do not ever bother to add a case for it.
  switch (return_value) {
    case -EPIPE: return "broken_pipe";
    case -ECONNABORTED: return "connection_aborted";
    case -ECONNREFUSED: return "connection_refused";
    case -ECONNRESET: return "connection_reset";
    case -EHOSTUNREACH: return "host_unreachable";
    case -ENETDOWN: return "network_down";
    case -ENETRESET: return "network_reset";
    case -ENETUNREACH: return "network_unreachable";
    case -ETIMEDOUT: return "timed_out";
  }
  // clang-format off
  // All other cases map directly to I/O error.
  return "io_error";
}

void Server::on_connect(int64_t sock, const sockaddr *sa, socklen_t salen,
                        int return_value) noexcept {
  EMIT_INFO("connect(" << sock << ", " << sockaddr_to_string(sa, salen)
            << ") => " << ((return_value == 0) ? "no_error" :
                            errno_to_string(return_value)));
}

void Server::on_send(int64_t sock, const char *buf, size_t total,
                     int64_t return_value) noexcept {
  EMIT_INFO("send(" << sock << ", " << buffer_to_string(buf, total) << ") => "
            << ((return_value >= 0) ? std::to_string(return_value) :
                errno_to_string(return_value)));
}

void Server::on_recv(int64_t sock, char *buf, size_t maxlen,
                     int64_t return_value) noexcept {
  EMIT_INFO("recv(" << sock << ", " << buffer_to_string(buf, maxlen) << ") => "
            << ((return_value >= 0) ? std::to_string(return_value) :
                errno_to_string(return_value)));
}

void Server::on_closesocket(int64_t sock, int return_value) noexcept {
  EMIT_INFO("close(" << sock << ") => "
                     << ((return_value) ? errno_to_string(return_value)
                                        : "no_error"));
}

#ifdef LIBSOCKS5_HAVE_GETDNS
class CharStarDeleter {
 public:
  // Implementation note: not all free() implementations handle `nullptr`
  void operator()(char *ptr) noexcept { if (ptr) ::free(ptr); }
};
using UniqueCharStar = std::unique_ptr<char, CharStarDeleter>;

void Server::on_getdns_success(getdns_dict *reply) noexcept {
  UniqueCharStar string_scope;
  // The returned string must be deleted with free() unless the default malloc
  // function has been replaced. See getdns documentation for more.
  auto s = getdns_pretty_print_dict(reply);
  string_scope.reset(s);
  EMIT_INFO(s);
}
#endif  // LIBSOCKS5_HAVE_GETDNS

static std::string hexdump(std::string record) noexcept {
  std::stringstream ss;
  for (uint64_t offset = 0;;) {
    ss << std::setw(8) << std::setfill('0') << std::hex
       << offset << "  ";
    for (uint64_t i = 0; i < 8; ++i) {
      if (offset <= UINT64_MAX - i && offset + i < record.size()) {
        ss << std::setw(2) << std::setfill('0') << std::hex
           << (uint64_t)(uint8_t)record[offset + i] << " ";
      } else {
        ss << "   ";
      }
    }
    ss << " ";
    for (uint64_t i = 8; i < 16; ++i) {
      if (offset <= UINT64_MAX - i && offset + i < record.size()) {
        ss << std::setw(2) << std::setfill('0') << std::hex
           << (uint64_t)(uint8_t)record[offset + i] << " ";
      } else {
        ss << "   ";
      }
    }
    ss << " |";
    for (uint64_t i = 0; i < 16; ++i) {
      if (offset <= UINT64_MAX - i && offset + i < record.size() &&
          record[offset + i] >= ' ' && record[offset + i] <= '~') {
        ss << (uint8_t)record[offset + i];
      } else {
        ss << " ";
      }
    }
    ss << "|";
    if (offset > UINT64_MAX - 16) break;
    offset += 16;
    if (offset >= record.size()) break;
    ss << std::endl;
  }
  return ss.str();
}

void Server::on_tls_handshake_cert(std::string record) noexcept {
  EMIT_INFO(hexdump(std::move(record)));
}

// Protected API
// `````````````

void Server::on_warning(std::string message) noexcept {
  std::clog << "[W] " << message << std::endl;
}

void Server::on_info(std::string message) noexcept {
  std::clog << message << std::endl;
}

void Server::on_debug(std::string message) noexcept {
  std::clog << "[D] " << message << std::endl;
}

#ifdef LIBSOCKS5_HAVE_GETDNS
// GetDNS specific code
// ````````````````````
// The point of this code is to show that we can replace DNS name resolution
// using getdns (and possibly other mechanisms) and that, as a result, we can
// obtain more interesting data _without_ changing the specific logic of a
// client such as OONI's WebConnectivity engine.

class GetdnsCtxDeleter {
 public:
  void operator()(getdns_context *ctx) noexcept { getdns_context_destroy(ctx); }
};
using UniqueGetdnsCtx = std::unique_ptr<getdns_context, GetdnsCtxDeleter>;

class GetdnsDictDeleter {
 public:
  void operator()(getdns_dict *dct) noexcept { getdns_dict_destroy(dct); }
};
using UniqueGetdnsDict = std::unique_ptr<getdns_dict, GetdnsDictDeleter>;

int  //
Server::so_resolve_hostname_getdns(
    std::string hostname, std::vector<std::string> *addresses) noexcept {
  EMIT_DEBUG("so_resolve_hostname_getdns: using getdns to resolve: " << hostname);
  // Create and configure the getdns context
  UniqueGetdnsCtx context_scope;
  getdns_context *ctxp = nullptr;
  if (::getdns_context_create(&ctxp, 1) != 0) {
    EMIT_WARNING("so_resolve_hostname_getdns: can't create getdns context");
    return -EIO;
  }
  assert(ctxp != nullptr);
  context_scope.reset(ctxp);
  EMIT_DEBUG("so_resolve_hostname_getdns: getdns context created");
  constexpr auto resolution = GETDNS_RESOLUTION_STUB;
  if (::getdns_context_set_resolution_type(ctxp, resolution) != 0) {
    EMIT_WARNING(
        "so_resolve_hostname_getdns: cannot configure getdns to act as "
        "a stub DNS resolver");
    return -EIO;
  }
  EMIT_DEBUG("so_resolve_hostname_getdns: getdns configured as stub resolver");
  // Perform one or more DNS queries
  getdns_dict *resp = nullptr;
  UniqueGetdnsDict response_scope;
  if (::getdns_address_sync(ctxp, hostname.data(), nullptr, &resp) != 0) {
    // The return value is not particularly interesting in this case because
    // of course getdns run many queries and it cannot tell us exactly what
    // went wrong. However we can perhaps have a conversation with them so that
    // we can include in the result dict also information on network errors?
    EMIT_WARNING("so_resolve_hostname_getdns: sync DNS query failed");
    return -EIO;
  }
  assert(resp != nullptr);
  response_scope.reset(resp);
  EMIT_DEBUG("so_resolve_hostname_getdns: done running queries");
  if ((impl->settings.options & option_trace) != 0) on_getdns_success(resp);
  // Process just_address_results to fill *addresses
  {
    getdns_list *jaa = nullptr;
    if (::getdns_dict_get_list(resp, "just_address_answers", &jaa) != 0) {
      EMIT_WARNING(
          "so_resolve_hostname_getdns: cannot get just_address_answers list");
      return -EIO;
    }
    getdns_dict *d = nullptr;
    for (size_t i = 0; (::getdns_list_get_dict(jaa, i, &d)) == 0; ++i) {
      getdns_bindata *a = nullptr;
      if (::getdns_dict_get_bindata(d, "address_data", &a) != 0) {
        EMIT_WARNING("so_resolve_hostname_getdns: cannot get address bindata");
        return -EIO;
      }
      UniqueCharStar string_scope;
      auto s = getdns_display_ip_address(a);
      if (s == nullptr) {
        EMIT_WARNING("so_resolve_hostname_getdns: cannot serialize IP address");
        return -EIO;
      }
      string_scope.reset(s);
      addresses->push_back(s);
    }
  }
  return (addresses->size() == 0) ? -EIO : 0;
}

#endif  // LIBSOCKS5_HAVE_GETDNS

int Server::so_resolve_hostname(
        std::string hostname, std::vector<std::string> *addresses) noexcept {
  if (addresses == nullptr) return -EINVAL;
  if ((impl->settings.options & option_getdns) != 0) {
#ifdef LIBSOCKS5_HAVE_GETDNS
    auto rv = so_resolve_hostname_getdns(hostname, addresses);
    if (rv == 0) return rv;
    if ((impl->settings.options & option_dns_fallback) == 0) return rv;
#else
    EMIT_WARNING("resolve_hostname: getdns support not compiled in");
    if ((impl->settings.options & option_dns_fallback) == 0) return -ENOTSUP;
#endif  // LIBSOCKS5_HAVE_GETDNS
    EMIT_DEBUG("resolve_hostname: getdns failed; falling back to getaddrinfo");
  }
  EMIT_DEBUG("resolve_hostname: using getaddrinfo to resolve: " << hostname);
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags |= AI_NUMERICSERV;
  hints.ai_family = AF_UNSPEC;
  addrinfo *rp = nullptr;
  // Implementation note: any port would be okay in this context.
  if (so_getaddrinfo(hostname.data(), "80", &hints, &rp) != 0) return -ENOENT;
  assert(rp != nullptr);
  for (auto ai = rp; ai != nullptr; ai = ai->ai_next) {
    char hostname[NI_MAXHOST];
    if (::getnameinfo(ai->ai_addr, ai->ai_addrlen, hostname, NI_MAXHOST,
                nullptr, 0, NI_NUMERICHOST) != 0) {
      return -EIO;
    }
    addresses->push_back(hostname);
  }
  return 0;
}

int Server::so_getaddrinfo(const char *hostname, const char *servname,
        const addrinfo *hints, addrinfo **rp) noexcept {
  return (::getaddrinfo(hostname, servname, hints, rp) != 0) ? -ENOENT : 0;
}

void Server::so_freeaddrinfo(addrinfo *rp) noexcept {
  return ::freeaddrinfo(rp);
}

int64_t Server::so_socket(int domain, int type, int protocol) noexcept {
  // Here we cannot return an error code because on Windows all values are
  // valid except from -1 that indicates the invalid socket.
  return (int64_t)::socket(domain, type, protocol);
}

// This function is "quick" because it performs less checks than needed and it
// should generally be used only right after a socket has been created.
int Server::so_setoptions_common_quick(int64_t fd) noexcept {
#ifdef _WIN32
  unsigned long enable = 1;
  return ::ioctlsocket(fd, FIONBIO, &enable) != 0 ? -EIO : 0;
#else
  if (::fcntl(fd, F_SETFL, O_NONBLOCK | ::fcntl(fd, F_GETFL)) != 0) {
    return -EIO;
  }
#ifdef SO_NOSIGPIPE  // Avoid SIGPIPE on BSD systems
  auto on = 1;
  if (::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)) != 0) {
    return -EIO;
  }
#endif               // SO_NOSIGPIPE
  return 0;
#endif               // _WIN32
}

int Server::so_closesocket(int64_t fd) noexcept {
  // TODO(bassosimone): consider the possibility of using SO_LINGER. This could
  // be a way to avoid the problem of "dirty shutdowns" (i.e. the fact that
  // control messages are not authenticated in TCP hence a malicious actor can
  // inject a FIN or RST into the flow thus terminating the connection).
#ifdef _WIN32
  return ::closesocket(fd) != 0 ? -EIO : 0;
#else
  return ::close(fd) != 0 ? -EIO : 0;
#endif
}

// clang-format off
// The following mapping mainly considers the errors that we most likely care
// about when measuring network interference, plus a couple of helpers.
static int map_last_error(int err) noexcept {
#ifdef _WIN32
#define E(name) WSAE##name
#else
#define E(name) E##name
#endif
#define CASE(name) case E(name): return -E##name
  switch (err) {
#ifndef _WIN32  // Not available on Windows
    CASE(PIPE);
#endif
    CASE(CONNABORTED);
    CASE(CONNREFUSED);
    CASE(CONNRESET);
    CASE(HOSTUNREACH);
    CASE(INTR);
    CASE(INVAL);
#ifndef _WIN32  // Not available on Windows
    CASE(IO);
#endif
    CASE(NETDOWN);
    CASE(NETRESET);
    CASE(NETUNREACH);
    // Simplify handling of errors by coalescing several retryable error
    // conditions into a single error code, i.e., -EAGAIN.
#ifdef _WIN32
    case WSAEINPROGRESS:
    case WSAEWOULDBLOCK:
      return -EAGAIN;
#else
    case EINPROGRESS:
    case EAGAIN:
#if EAGAIN != EWOULDBLOCK
    case EWOULDBLOCK:
#endif
      return -EAGAIN;
#endif
    CASE(TIMEDOUT);
  }
#undef CASE
#undef E
  return -EIO;  // By default it's an I/O error
}
// clang-format on

static int get_last_error() noexcept {
#ifdef _WIN32
  return map_last_error(::GetLastError());
#else
  return map_last_error(errno);
#endif
}

int Server::so_bind(int64_t fd, const sockaddr *sa, socklen_t len) noexcept {
  return ::bind(fd, sa, len) != 0 ? -EIO : 0;
}

int Server::so_connect(int64_t fd, const sockaddr *sa, socklen_t len) noexcept {
  // On some systems connect() may complete immediately for localhost so it
  // may still be useful to keep proper mapping of the error code. However in
  // practice I doubt that will be useful for OONI measurements.
  return ::connect(fd, sa, len) != 0 ? get_last_error() : 0;
}

int Server::so_poll(pollfd *fds, uint64_t nfds, int milli) noexcept {
  // Arbitrarily limit nfds to a very small value and later force a cast so we
  // don't have to do effort to consider Win32/Unix real sizes. We're not going
  // to have more than a bunch of sockets to poll anyway.
  if (nfds > USHRT_MAX) return -EOVERFLOW;
#ifdef _WIN32
  auto rv = ::WSAPoll(fds, (unsigned short)nfds, milli);
#else
  auto rv = 0;
again:
  rv = ::poll(fds, (unsigned short)nfds, milli);
  if (rv == -1 && errno == EINTR) goto again;
#endif
  return (rv < 0) ? -EIO : (rv == 0) ? -ETIMEDOUT : 0;
}

int Server::so_wait_flags(int64_t fd, short flags, int milli) noexcept {
  pollfd pfd{};
  pfd.fd = fd;
  pfd.events = flags;
  auto err = so_poll(&pfd, 1, milli);
  // Fail in case we have passed an invalid socket descriptor to poll().
  return (err) ? err : (pfd.revents & POLLNVAL) != 0 ? -EINVAL : 0;
}

int Server::so_wait_writeable(int64_t fd, int milli) noexcept {
  return so_wait_flags(fd, POLLOUT, milli);
}

int Server::so_wait_readable(int64_t fd, int milli) noexcept {
  return so_wait_flags(fd, POLLIN, milli);
}

int Server::so_getsockopt(int64_t fd, int level, int option_name,
                          char *option_value, socklen_t *option_len) noexcept {
  return ::getsockopt(fd, level, option_name,
                      option_value, option_len) != 0
             ? -EIO
             : 0;
}

int Server::so_setsockopt(int64_t fd, int level, int option_name,
                          char *option_value, socklen_t option_len) noexcept {
  return ::setsockopt(fd, level, option_name,
                      option_value, option_len) != 0
             ? -EIO
             : 0;
}

int64_t Server::so_recv_nonblock(int64_t fd, char *p, uint64_t n) noexcept {
  if (n > INT_MAX) return -EOVERFLOW;  // Limitation on Windows
  auto rv = ::recv(fd, p, (unsigned int)n, 0);
  return (rv < 0) ? get_last_error() : (int64_t)rv;
}

// Curiosity: in libndt I use a proactive pattern because it avoids waiting
// when you're receiving in a loop. Here speed matters less, so use a reactive
// pattern because it's simpler and easier to read.
int64_t Server::so_recv(int64_t fd, char *p, uint64_t n) noexcept {
  auto r = (int64_t)so_wait_readable(fd, impl->settings.timeout_millisecond);
  if (r == 0) r = so_recv_nonblock(fd, p, n);
  return r;
}

int64_t Server::so_recvn(int64_t fd, char *p, uint64_t n) noexcept {
  uint64_t o = 0ULL;
  while (o < n) {
    if ((uintptr_t)p > UINTPTR_MAX - o) return -EOVERFLOW;
    int64_t c = so_recv(fd, p + o, n - o);
    if (c <= 0) return c;
    if (o > UINT64_MAX - c) return -EOVERFLOW;
    o += (uint64_t)c;
  }
  if (o > INT64_MAX) return -EOVERFLOW;
  return (int64_t)o;
}

int64_t Server::so_send_nonblock(int64_t fd, const char *p,
                                 uint64_t n) noexcept {
  if (n > INT_MAX) return -EOVERFLOW;  // Limitation on Windows
#ifdef MSG_NOSIGNAL                    // Linux trick to avoid SIGPIPE
  auto rv = ::send(fd, p, (unsigned int)n, MSG_NOSIGNAL);
#else
  auto rv = ::send(fd, p, (unsigned int)n, 0);
#endif
  return (rv < 0) ? get_last_error() : (int64_t)rv;
}

// Make sure we do not compile if we cannot ignore SIGPIPE
#if !defined _WIN32 && !defined SO_NOSIGPIPE && !defined MSG_NOSIGNAL
#error "No way to avoid SIGPIPE on your system. Damn."
#endif  // Not Windows, not BSD, not Linux.

int64_t Server::so_send(int64_t fd, const char *p, uint64_t n) noexcept {
  auto r = (int64_t)so_wait_writeable(fd, impl->settings.timeout_millisecond);
  if (r == 0) r = so_send_nonblock(fd, p, n);
  return r;
}

int64_t Server::so_sendn(int64_t fd, const char *p, uint64_t n) noexcept {
  uint64_t o = 0ULL;
  while (o < n) {
    if ((uintptr_t)p > UINTPTR_MAX - o) return -EOVERFLOW;
    int64_t c = so_send(fd, p + o, n - o);
    if (c <= 0) return c;
    if (o > UINT64_MAX - c) return -EOVERFLOW;
    o += (uint64_t)c;
  }
  if (o > INT64_MAX) return -EOVERFLOW;
  return (int64_t)o;
}

int64_t Server::so_accept(int64_t fd, sockaddr *n, socklen_t *ln) noexcept {
  // As for connect, here the only invalid value is -1.
  return ::accept(fd, n, ln);
}

// Private API
// ```````````

int Server::socks5h_dispatch(int64_t clientfd) noexcept {
  if (clientfd == -1) return -EINVAL;
  {
    EMIT_DEBUG("socks5h_dispatch: reading socks version");
    uint8_t version = 0;
    if (so_recvn(clientfd, (char *)&version, sizeof(version)) <= 0) {
      EMIT_WARNING("socks5h_dispatch: so_recvn() failed");
      return -EIO;
    }
    if (version != 0x05) {
      EMIT_WARNING("socks5h_dispatch: unsupported socks version");
      return -ENOTSUP;
    }
    EMIT_DEBUG("socks5h_dispatch: got socks version: " << (uint64_t)version);
  }
  {
    EMIT_DEBUG("socks5h_dispatch: read auth methods");
    uint8_t len = 0;
    if (so_recvn(clientfd, (char *)&len, sizeof(len)) <= 0) {
      EMIT_WARNING("socks5h_dispatch: so_recvn() failed");
      return -EIO;
    }
    EMIT_DEBUG("socks5h_dispatch: auth methods length: " << (uint64_t)len);
    if (len <= 0) {
      EMIT_WARNING("socks5h_dispatch: invalid auth methods length");
      return -EPROTO;
    }
    bool found_noauth = false;
    for (; len > 0; len -= 1) {
      uint8_t auth = 0;
      if (so_recvn(clientfd, (char *)&auth, sizeof(auth)) <= 0) {
        EMIT_WARNING("socks5h_dispatch: so_recvn() failed");
        return -EIO;
      }
      EMIT_DEBUG("socks5h_dispatch: auth method: " << (uint64_t)auth);
      found_noauth = found_noauth || (auth == 0x00);
    }
    if (!found_noauth) {
      EMIT_WARNING("socks5h_dispatch: no supported auth methods; failing");
      return -ENOTSUP;
    }
  }
  {
    EMIT_DEBUG("sending greetings response");
    uint8_t reply[] = {0x05, 0x00};
    if (so_sendn(clientfd, (char *)reply, sizeof(reply)) <= 0) {
      EMIT_WARNING("socks5h_dispatch: so_sendn() failed");
      return -EIO;
    }
  }
  {
    EMIT_DEBUG("socks5h_dispatch: receiving connect request header");
    uint8_t header[4];
    if (so_recvn(clientfd, (char *)header, sizeof(header)) <= 0) {
      EMIT_WARNING("socks5h_dispatch: so_recvn() failed");
      return -EIO;
    }
    if (header[0] != 0x05) {
      EMIT_WARNING("socks5h_dispatch: unsupported socks version");
      return -ENOTSUP;
    }
    if (header[1] != 0x01) {
      EMIT_WARNING("socks5h_dispatch: unsupported command code");
      return -ENOTSUP;
    }
    if (header[2] != 0x00) {
      EMIT_WARNING("socks5h_dispatch: invalid reserved field");
      return -EPROTO;
    }
    if (header[3] != 0x03) {
      EMIT_WARNING("socks5h_dispatch: unsupported address type: "
                   << (uint64_t)header[3]);
      return -ENOTSUP;
    }
    EMIT_DEBUG("socks5h_dispatch: successfully read connect request header");
  }
  std::string hostname;
  {
    EMIT_DEBUG("socks5h_dispatch: getting hostname");
    uint8_t len = 0;
    if (so_recvn(clientfd, (char *)&len, sizeof(len)) <= 0) {
      EMIT_WARNING("socks5h_dispatch: so_recvn() failed");
      return -EIO;
    }
    if (len == 0) {
      EMIT_WARNING("socks5h_dispatch: length is too short");
      return -EPROTO;
    }
    uint8_t buffer[UINT8_MAX];
    if (so_recvn(clientfd, (char *)buffer, len) <= 0) {
      EMIT_WARNING("socks5h_dispatch: so_recvn() failed");
      return -EIO;
    }
    hostname = std::string{(char *)buffer, len};
    EMIT_DEBUG("socks5h_dispatch: got hostname: " << hostname);
  }
  std::string port;
  {
    EMIT_DEBUG("socks5h_dispatch: getting port");
    uint16_t value = 0;
    if (so_recvn(clientfd, (char *)&value, sizeof(value)) <= 0) {
      EMIT_WARNING("socks5h_dispatch: so_recvn() failed");
      return -EIO;
    }
    value = ntohs(value);
    port = std::to_string(value);
    EMIT_DEBUG("socks5h_dispatch: got port: " << port);
  }
  {
    EMIT_DEBUG("socks5h_dispatch: making sure there is no extra data");
    uint8_t data = 0;
    if (so_recv_nonblock(clientfd, (char *)&data, sizeof(data)) != -EAGAIN) {
      EMIT_WARNING("socks5h_dispatch: received more data than expected");
      return -EPROTO;
    }
    EMIT_DEBUG("socks5h_dispatch: good, no extra data in buffer");
  }
  int64_t serverfd = -1;
  {
    EMIT_DEBUG("socks5h_dispatch: proceeding with connect");
    std::vector<std::string> addresses;
    // Implementation note: the reason why we have a "resolve hostname" step
    // followed by a "getaddrinfo" step, rather that doing everything with one
    // single getaddrinfo() call is that this enables us to perform DNS name
    // resolution using different engines. Currently, the code already supports
    // using the getdns engine to collect more low-level information.
    if (so_resolve_hostname(hostname, &addresses) != 0) {
      EMIT_WARNING("socks5h_dispatch: cannot resolve: " << hostname);
      return -EIO;
    }
    for (auto &addr : addresses) {
      EMIT_DEBUG("socks5h_dispatch: try with " << addr);
      addrinfo hints{};
      hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
      hints.ai_socktype = SOCK_STREAM;
      addrinfo *rp = nullptr;
      if (so_getaddrinfo(addr.data(), port.data(), &hints, &rp) != 0) {
        EMIT_WARNING("socks5h_dispatch: cannot parse address: " << addr);
        continue;
      }
      assert(rp != nullptr);
      for (auto ai = rp; ai != nullptr; ai = ai->ai_next) {
        auto fd = so_socket(ai->ai_family, ai->ai_socktype, 0);
        if (fd == -1) {
          EMIT_WARNING("socks5h_dispatch: so_socket() failed");
          continue;
        }
        EMIT_DEBUG("socks5h_dispatch: socket created");
        if (so_setoptions_common_quick(fd) != 0) {
          (void)so_closesocket(fd);
          EMIT_WARNING("socks5h_dispatch: so_setoptions() failed");
          continue;
        }
        EMIT_DEBUG("socks5h_dispatch: common options set");
        auto err = so_connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (err != 0 && err != -EAGAIN) {
          (void)so_closesocket(fd);
          // As mentioned above, since this is a nonblocking connect, the error
          // will not be very interesting in 99.9% of the cases.
          EMIT_WARNING("socks5h_dispatch: so_connect() failed: " << err);
          continue;
        }
        EMIT_DEBUG("socks5h_dispatch: connect in progress");
        if (so_wait_writeable(fd, impl->settings.timeout_millisecond) != 0) {
          (void)so_closesocket(fd);
          EMIT_WARNING("socks5h_dispatch: so_wait_writeable() failed");
          continue;
        }
        EMIT_DEBUG("socks5h_dispatch: finished waiting for writeability");
        int soerr = 0;
        socklen_t soerrlen = sizeof(soerr);
        if (so_getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&soerr,
                          &soerrlen) != 0) {
          (void)so_closesocket(fd);
          EMIT_WARNING("socks5h_dispatch: so_getsockopt() failed");
          continue;
        }
        if ((impl->settings.options & option_trace) != 0) {
          on_connect(fd, ai->ai_addr, ai->ai_addrlen,
                     (soerr) ? map_last_error(soerr) : 0);
        }
        if (soerr == 0) {
          EMIT_DEBUG("socks5h_dispatch: we successfully connected to "
                     << addr << " on port " << port);
          serverfd = fd;
          break;
        }
        // On the contrary, the error that we have here is the actual error
        // that really prevented connect() from succeding.
        (void)so_closesocket(fd);
        EMIT_WARNING("socks5h_dispatch: connect() actually failed: "
                     << map_last_error(soerr));
      }
      so_freeaddrinfo(rp);  // Do not leak
      if (serverfd != -1) {
        break;  // Exit from the outer loop
      }
    }
  }
  EMIT_DEBUG("socks5h_dispatch: sending connect response to client");
  {
    // We return to the client an all zeroed address and port, like Tor does.
    uint8_t buf[] = {
        0x05,                    // version
        0x00,                    // result
        0x00,                    // reserved
        0x01,                    // address type IPv4
        0x00, 0x00, 0x00, 0x00,  // IPv4 (4 bytes)
        0x00, 0x00               // port
    };
    if (serverfd == -1) {
      buf[1] = 0x01;  // Generic error
    }
    if (so_sendn(clientfd, (char *)buf, sizeof(buf)) <= 0) {
      EMIT_WARNING("socks5h_dispatch: so_sendn() failed");
      if (serverfd != -1) (void)so_closesocket(serverfd);
      return -EIO;
    }
    if (serverfd == -1) {
      EMIT_WARNING("socks5h_dispatch: stopping here because connect failed");
      // No need to close any socket on this error path :^)
      return -EIO;
    }
  }
  {
    EMIT_DEBUG("socks5h_dispatch: now forward traffic");
    std::atomic<uint64_t> active{2};
    constexpr uint8_t trace_receive = (1 << 0);
    constexpr uint8_t trace_send = (1 << 1);
    auto forward = [&active, this ](  //
        uint64_t source, uint64_t sink, uint8_t trace) noexcept {
      char buffer[131072];
      constexpr uint64_t tls_snap_size = 262144;  // TODO(bassosimone): ok?
      std::string tls_stream;
      while (!impl->interrupted) {
        auto n = so_recv(source, buffer, sizeof(buffer));
        if ((trace & trace_receive) != 0) {
          on_recv(source, buffer, sizeof(buffer), n);
          if (n > 0 && tls_stream.size() < tls_snap_size) {
            // The snap size is not enforced strictly. It doesn't matter.
            tls_stream += std::string{buffer, (uint64_t)n};
            if (tls_stream.size() >= tls_snap_size) decode_tls(tls_stream);
          }
        }
        if (n <= 0) break;
        auto actual = (uint64_t)n;
        n = so_sendn(sink, buffer, actual);
        if ((trace & trace_send) != 0) {
          on_send(sink, buffer, actual, n);
        }
        if (n <= 0) break;
      }
      if ((trace & trace_receive) != 0 &&
          tls_stream.size() < tls_snap_size) decode_tls(tls_stream);
      active -= 1;
    };
    // clang-format off
    std::thread{
        forward, clientfd, serverfd,
        (impl->settings.options & option_trace) != 0 ? trace_send : 0
    }.detach();
    std::thread{
        forward, serverfd, clientfd,
        (impl->settings.options & option_trace) != 0 ? trace_receive : 0
    }.detach();
    // clang-format on
    /*-
     * Art by Marcin Glinski
     *                                            _.gd8888888bp._
     *                                         .g88888888888888888p.
     *                                       .d8888P""       ""Y8888b.
     *                                       "Y8P"               "Y8P'
     *                                          `.               ,'
     *                                            \     .-.     /
     *                                             \   (___)   /
     *  .------------------._______________________:__________j
     * /                   |                      |           |`-.,_
     * \###################|######################|###########|,-'`
     *  `------------------'                       :    ___   l
     *                                             /   (   )   \
     *                                    fsc     /     `-'     \
     *                                          ,'               `.
     *                                       .d8b.               .d8b.
     *                                       "Y8888p..       ,.d8888P"
     *                                         "Y88888888888888888P"
     *                                            ""YY8888888PP""
     *
     * This is meant to say: I know the code below is not a fancy solution but
     * I don't care because it's simple, does its job, and does not consume
     * resources. (Yeah, you can argue that on mobile this isn't good and on
     * that I concur, but the plan is to shutdown most if not all the C++ code
     * in the OONI app when it's not running tests ¯\_(ツ)_/¯).
     *
     *              [Art source: <https://www.asciiart.eu/weapons/axes>.]
     */
    while (active > 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
  }
  auto rv = so_closesocket(serverfd);
  if ((impl->settings.options & option_trace) != 0) {
    on_closesocket(serverfd, rv);
  }
  return 0;
}

void Server::decode_tls(const std::string &data) noexcept {
  // See <https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-socket-layer-ssl/116181-technote-product-00.html>
  //
  // Note that according to the above source Microsoft is known to violate the
  // maximum record length ((1 << 14) -1) thus we don't enforce limits.
  //
  // Decoding of protocols older than SSLv3 is not implemented.
  uint64_t limit = data.size();
  const char *base = data.data();
  for (;;) {
    std::string record;                  //
    if (limit < 5) return;               // No space for fixed fields
    if (base[0] != 0x16) return;         // Not a handshake record
    record += base[0];                   //
    if (base[1] != 0x03) return;         // Not TLS v1.x compatible
    record += base[1];                   //
    if (base[2] != 0x00 &&               // Not SSLv3
        base[2] != 0x01 &&               // Not TLSv1
        base[2] != 0x02 &&               // Not TLSv1.1
        base[2] != 0x03) {               // Not TLSv1.2+
      return;                            //
    }                                    //
    record += base[2];                   //
    uint16_t len = 0;                    //
    len += ((uint8_t)base[3]) << 8;      // Length in network byte order
    len += ((uint8_t)base[4]) << 0;      // Continuing to read length
    record += base[3];                   //
    record += base[4];                   //
                                         //
    if ((uintptr_t)base >                // Skip the fixed header
        UINTPTR_MAX - 5) return;         //
    base += 5;                           //
    assert(limit >= 5);                  //
    limit -= 5;                          //
    if (len > 0) {                       //
      if (len > limit) return;           // Truncated
      record += std::string{base, len};  //
      if (base[0] == 0x0b) {             // Search for certificate
        on_tls_handshake_cert(record);   //
        return;                          // Final state!
      }                                  //
      if ((uintptr_t)base >              // Skip the fixed body
          UINTPTR_MAX - len) return;     //
      base += len;                       //
      assert(len <= limit);              //
      limit -= len;                      //
    }                                    //
  }                                      //
}

#endif  // LIBSOCKS5_NO_INLINE_IMPL
}  // namespace libsocks5
}  // namespace measurement_kit
#endif  // MEASUREMENT_KIT_LIBSOCKS5_HPP
