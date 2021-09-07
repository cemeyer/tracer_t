// Summary of background / options:
// 1. Historical traceroute is UDP -> high port with low TTLs, which induce an ICMP response from
//    the routers in the middle.
//    a. One alternative is just sending ICMP echos instead of UDP packets to induce the responses.
//    b. A second alternative is using TCP connections on a well-known port (e.g., 80) to avoid
//       firewalls.  An optimization is to only send SYN packets, to avoid the overhead of
//       establishing connections and potentially confusing some web server at the end of the
//       probe.  However, the optimization requires privileges to send raw packets.
// 2. ICMP doesn't have ports, so:
//    a. Historically, OSes have required ICMP receivers to snoop all packets with a Raw socket,
//       which obviously requires elevated privileges.
//    b. 1/2 newer refinements is IPPROTO_ICMP in Linux, which allows one to send icmp packets to
//       some address and receive responses from the same address, without extra privileges.
//       However, this is not useful for traceroute because error responses from earlier hops are
//       not forwarded by the kernel to our unprivileged socket.
//    c. 2/2 newer refinements is IP_RECVERR on UDP sockets, which allows us to receive associated
//       ICMP error responses for a send.
//
// XXX We have elected to go with UDP -> ICMP via IP_RECVERR, to (primarily) avoid needing elevated
// privileges; and (secondarily) to avoid the overhead of attempting to open many TCP connections.

#![allow(dead_code, unused_imports, unused_variables)]

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::env;
use std::iter::FromIterator;
use std::net::SocketAddr;
use std::os::unix::prelude::*;
use anyhow::Result;
use nix::errno::Errno;
use nix::poll::{self, PollFd, PollFlags};
use nix::sys::socket::{self, *};
use nix::sys::uio::IoVec;
use nix::unistd;

#[derive(Debug)]
struct Config {
    ttl_max: u8,
    num_probes: u32,
    port_lo: u16,
}

// XXX: may be able to reduce number of sockets.
#[derive(Debug)]
struct Probe {
    socket: RawFd,
    ttl: u8,
    // timeout / elapsed?
}

impl Drop for Probe {
    fn drop(&mut self) {
        unistd::close(self.socket).unwrap();
    }
}

impl Probe {
    fn new(ttl: u8) -> Result<Self> {
        let socket = socket::socket(AddressFamily::Inet,
                                    SockType::Datagram,
                                    SockFlag::SOCK_NONBLOCK,
                                    None)?;
        setsockopt(socket, sockopt::Ipv4RecvErr, &true).unwrap();
        let ttl32 = i32::from(ttl);
        setsockopt(socket, sockopt::Ipv4Ttl, &ttl32).unwrap();
        Ok(Self {
            socket,
            ttl,
        })
    }

    fn fire(&mut self, config: &Config, dst: IpAddr) -> Result<()> {
        let dst = SockAddr::new_inet(InetAddr::new(dst, config.port_lo + self.ttl as u16));
        sendto(self.socket, &[1,2,3,4], &dst, MsgFlags::empty())?;

        // XXX start elapsed timer, compute timeout Instant

        Ok(())
    }
}

#[derive(Clone, Debug, Copy)]
enum ProbeResult {
    Timeout,
    Response {
        from: IpAddr,
        error: Errno,
        terminal: bool,
        print_x: bool,
    },
    // latency?
}

#[derive(Debug)]
struct State {
    // List of active probes, unordered
    probes: Vec<Probe>,
    // [ttl] -> Vec of results
    results: Vec<Vec<ProbeResult>>,
    // Most recently printed line
    last_printed: u8,
    // Printed a terminal line
    was_terminal: bool,
}

fn send_probes(config: &Config, state: &mut State, target: IpAddr) -> Result<()> {
    state.results.resize(usize::from(config.ttl_max) + 1, Vec::new());
    for ttl in 1..=config.ttl_max {
        for probe in 0..config.num_probes {
            state.probes.push(Probe::new(ttl)?);
        }
    }

    for probe in state.probes.iter_mut() {
        probe.fire(config, target)?;
    }

    Ok(())
}

// XXX: global timeout?
fn check_readiness(config: &Config, state: &mut State) -> Result<Vec<RawFd>> {
    let mut pfds = state.probes.iter().map(|p| PollFd::new(p.socket, PollFlags::POLLIN)).collect::<Vec<_>>();
    let n = poll::poll(&mut pfds, -1)?;

    let mut res = Vec::with_capacity(n as usize);
    for pfd in pfds.iter() {
        if !pfd.revents().unwrap().is_empty() {
            res.push(pfd.as_raw_fd());
        }
    }

    Ok(res)
}

fn print_result(ttl: u8, results: &Vec<ProbeResult>) {
    print!(" {} ", ttl);
    for r in results {
        match r {
            ProbeResult::Timeout => {
                print!(" *.");
            }
            ProbeResult::Response { from, error, terminal, print_x } => {
                let x = if *print_x { " !X" } else { "" };
                print!(" {}:{} {:?}, {}.", from, x, error, terminal);
            }
        }
    }
    println!();
}

// Shared packet buffer reused between individual processing.
struct RecvCache {
    buf: Vec<u8>,
    cmsg_space: Vec<u8>,
}

// ipv4
enum IcmpType {
    Unreachable = 3,
    TimeExceeded = 11,
}
enum IcmpCodeUnreach {
    Host = 1,
    Port = 3,
    AdminProhib = 13,
}
enum IcmpCodeTimeEx {
    Ttl = 0,
    FragmentReassmbly = 1,
}

// Process an fd.  If we should stop polling this fd, returns Ok(true).
fn process_ready_fd(config: &Config, state: &mut State, probe_idx: usize, buf: &mut RecvCache) -> Result<bool> {
    let probe = &state.probes[probe_idx];
    let iovec = [IoVec::from_mut_slice(&mut buf.buf)];
    let msg = recvmsg(probe.socket, &iovec, Some(&mut buf.cmsg_space), MsgFlags::MSG_ERRQUEUE)?;

    let mut res = false;

    for cmsg in msg.cmsgs() {
        match cmsg {
            ControlMessageOwned::Ipv4RecvErr(ee, addr) => {
                let addr = addr.map(|s| IpAddr::V4(Ipv4Addr(s.sin_addr)))
                    .ok_or(anyhow::Error::msg("missing origin"))?;

                let mut terminal = false;
                let mut print_x = false;

                if ee.ee_type == IcmpType::Unreachable as _ {
                    if ee.ee_code == IcmpCodeUnreach::Host as _ {
                        println!(">> Unreachable host from {}", addr);
                    } else if ee.ee_code == IcmpCodeUnreach::Port as _ {
                        //println!(">> Normal unreachable port from {}", addr);
                        terminal = true;
                    } else if ee.ee_code == IcmpCodeUnreach::AdminProhib as _ {
                        println!(">> Unreachable via router (admin prohibited) from {}", addr);
                        terminal = true;
                        print_x = true;
                    } else {
                        println!(">> Unreachable (code {}) from {}", ee.ee_code, addr);
                    }
                } else if ee.ee_type == IcmpType::TimeExceeded as _ {
                    if ee.ee_code == IcmpCodeTimeEx::Ttl as _ {
                        //println!(">> Normal ttl exceeded from {}", addr);
                    } else {
                        println!(">> Time exceeded (code {}) from {}", ee.ee_code, addr);
                    }
                } else {
                    println!("Unexpected Icmp type {} (code {}) from {}", ee.ee_type, ee.ee_code, addr);
                }

                let ttl_results = &mut state.results[probe.ttl as usize];
                ttl_results.push(ProbeResult::Response {
                    from: addr,
                    error: Errno::from_i32(ee.ee_errno as _),
                    terminal,
                    print_x,
                });
                for (ttl, results) in state.results.iter().enumerate().skip(probe.ttl as _) {
                    let ttl = u8::try_from(ttl).unwrap();
                    if results.len() == config.num_probes as _ && state.last_printed + 1 == ttl {
                        print_result(ttl, results);
                        state.last_printed += 1;

                        if results.iter().any(|r| {
                            match r {
                                ProbeResult::Response { terminal, .. } => *terminal,
                                _ => false,
                            }
                        }) {
                            state.was_terminal = true;
                            break;
                        }
                    } else {
                        break;
                    }
                }

                res = true;
            }
            _ => {
                println!("Unexpected cmsg {:?}", cmsg);
            }
        }
    }

    Ok(res)
}

fn process_ready_fds(config: &Config, state: &mut State, ready: Vec<RawFd>) -> Result<()> {
    // without this turbofish stupidity the compiler does not use the default 2nd type parameter to
    // HashSet.
    let ready = HashSet::<_>::from_iter(ready);
    let mut recvbuf = RecvCache {
        buf: vec![0u8; 576],
        cmsg_space: nix::cmsg_space!(libc::sock_extended_err, libc::sockaddr_in),
    };

    let mut i = 0;
    while i < state.probes.len() {
        if ready.contains(&state.probes[i].socket) && process_ready_fd(config, state, i, &mut recvbuf)? {
            state.probes.swap_remove(i);
            if state.was_terminal {
                break;
            }
        } else {
            i += 1;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let addr = IpAddr::from_std(&env::args().nth(1).unwrap().parse()?);
    let config = Config { num_probes: 1, ttl_max: 12, port_lo: 33433, };
    let mut state = State {
        probes: Vec::new(),
        results: Vec::new(),
        last_printed: 0,
        was_terminal: false,
    };

    println!("tracer_t to {}, {} hops max", addr, config.ttl_max);

    send_probes(&config, &mut state, addr)?;

    loop {
        // XXX make state.probes associative so we can scan faster
        let readyset = check_readiness(&config, &mut state)?;

        if !readyset.is_empty() {
            process_ready_fds(&config, &mut state, readyset)?;
        }

        if state.was_terminal {
            break;
        }
    }

    Ok(())
}
