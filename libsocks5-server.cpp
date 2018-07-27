// Part of Measurement Kit <https://measurement-kit.github.io/>.
// Measurement Kit is free software under the BSD license. See AUTHORS
// and LICENSE for more information on the copying conditions.

#include "libsocks5.hpp"

using namespace measurement_kit;

int main() {
  libsocks5::Settings settings;
  settings.verbosity = libsocks5::verbosity_info;
  settings.parallelism = 200;
  settings.options |= libsocks5::option_getdns |
                      libsocks5::option_dns_fallback |
                      libsocks5::option_trace;
  libsocks5::Server server{std::move(settings)};
  server.run();
}
