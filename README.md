Building a DNS server in Rust
=============================

To me, DNS is one the most exciting aspects of the Internet. Before it was
invented, everyone on the internet - which admittedly wasn't that many at that
stage - relied on a shared file called HOSTS.TXT, maintained by the Stanford
Research Institute. This file was synchronized manually through FTP, and as the
number of hosts grew, so did the rate of change and the unfeasibility of the
system. In 1983, Paul Mockapetris set out to find a long term solution to the
problem and went on to design and implement DNS. It's a testament to his
genius that the his creation has been able to scale from a few thousand
computers to the Internet as we know it today.

With the combined goal of gaining a deep understanding of DNS, of doing
something interesting with Rust, and of scratching some of my own itches,
I originally set out to implement my own DNS server. This document is not
a truthful chronicle of that journey, but rather an idealized version of it,
without all the detours I ended up taking. We'll gradually implement a full
DNS server, starting from first principles.

 * [Chapter 1 - The DNS protocol](/src/bin/chapter1.md)
 * [Chapter 2 - Building a stub resolver](/src/bin/chapter2.md)
