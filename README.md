# Simple socks5 server for OONI

The idea is to tell WebConnectivity (or possibly cURL or a browser) that
it should use this socks5h server as a proxy. Then, from the privileged
position of the proxy we can perform some measurements like:

1. seeing most network events regardless of the library or the framework
   actually used to perform the measurements

2. possibility of using an alternative DNS resolver because socks5h is
   such that the domain name resolution is performed by the proxy

3. possiblity to extract the TLS certificate by reassembling the initial
   TLS traffic and with a less-than-100-loc parser

It is important to highlight that this is not meant to be a fancy, high
parallelism, high performance server. Quite the contrary. The code for
running the proxy itself must be as simple as possible, because there will
be complexity related to understanding network events and reacting with
follow-up measurements. In the corrent code, for example, we can use the
getdns resolver. If that fails, we currently just acknowledge that we
had a network issue. But in the future, in such case, we may want to start
a procedure for better understanding what's up with the DNS.

Speaking of the design, this is a single header C++11 library. This makes
it super simple to integrate it into the build of Measurement Kit.

