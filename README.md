# tracer_t
tracer_t is a toy Rust `traceroute(8)`, for Linux.

# Demo
```
$ tracer_t 8.8.8.8
tracer_t to 8.8.8.8, 12 hops max
 1  192.168.0.1  0.349 ms  0.460 ms  0.600 ms
 2  63.231.10.66  4.251 ms  4.296 ms  4.353 ms
 3  63.226.198.9  4.358 ms  4.396 ms  4.448 ms
 4  67.14.41.158  4.391 ms  4.448 ms  4.574 ms
 5  72.14.221.108  4.523 ms  4.670 ms 72.14.221.110  4.803 ms
 6  74.125.243.193  5.016 ms 10.252.164.126  5.585 ms 74.125.243.177  6.391 ms
 7  8.8.8.8  4.578 ms  4.722 ms  4.833 ms
```

# Mechanics
tracer_t sends UDP datagrams to the target IP address, on sequential,
high-numbered ports, with varying IP TTL (time to live) values.

tracer_t uses the Linux `IPPROTO_IP` `IP_RECVERR` socket option feature to
receive ICMP error results associated with the low-TTL probes from the Linux
kernel.  In addition to delegating some of the work to the kernel, this
approach is nice because it does not require elevated privileges.

## Concurrency

tracer_t blasts out all probes immediately, without rate-limiting, and then
uses the `poll(2)` system call to monitor responses without polling.  Output
lines are emitted when all probes for the next TTL have received responses, or
timed out.

## Timeouts

tracer_t employs the same max/here/near timeout mechanism as `traceroute(8)`.

Probes are subject to the minimum of several possible timeouts.  The first is
the 'max', which always applies (default 5 seconds).  Second, if any other
responses have been received for the same hop, the 'here' timeout is the
quickest response for the same hop multiplied by a small factor (default 3x).
Finally, the 'near' timeout is the quickest response for any subsequent hop
multiplied by a larger factor (default 10x).

This heuristic should work tolerably in consistently high-latency network
conditions, while being responsive in low-latency networks with some packet
loss, or with middleboxes that do not send ICMP Time Exceeded error responses.

# Dependencies
tracer_t depends on the nix, libc, and anyhow crates.  Of these, nix and libc
are essential; anyhow could be dropped.  Indirect dependencies are autocfg,
bitflags, cfg-if, and memoffset.
