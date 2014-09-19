jRuby Compatibility Issues
==========================

* Must use bundle install --without pcap development db
* PG constants are not the same between pg and jruby-pg (BadConnection, etc)
* Gemfile and gemspec changes to avoid incompatible gem loads
* The metasploit-concern gem is in the wrong group https://github.com/rapid7/metasploit-framework/issues/3831
* Socket::IPPROTO_TCP is not defined which will likely break Rex sockets in various places
* OpenSSL certificate signing throws a null pointer error
  * https://github.com/jruby/jruby/issues?q=is%3Aopen+is%3Aissue+openssl
* Differences between exception names and constants all over the place

Does it work?
=============

Nope.
