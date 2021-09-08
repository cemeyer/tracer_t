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
use std::time::{Duration, Instant};
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
    // These are initialized None, then set to Some() on ::fire().
    start: Option<Instant>,
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
            start: None,
        })
    }

    fn fire(&mut self, config: &Config, dst: IpAddr) -> Result<()> {
        let dst = SockAddr::new_inet(InetAddr::new(dst, config.port_lo + self.ttl as u16));
        let start = Instant::now();
        self.start = Some(start);
        sendto(self.socket, &[1,2,3,4], &dst, MsgFlags::empty())?;
        Ok(())
    }
}

// ipv4
#[derive(Clone, Debug, Copy)]
enum IcmpType {
    Unreachable = 3,
    TimeExceeded = 11,
}
#[derive(Clone, Debug, Copy)]
enum IcmpCodeUnreach {
    Network = 0,
    Host = 1,
    Protocol = 2,
    Port = 3,
    FragNeeded = 4,
    SourceRoute = 5,
    DestNetUnknown = 6,
    DestHostUnknown = 7,
    SourceHostIso = 8,
    DestAdminProhib = 9,
    HostAdminProhib = 10,
    NetTypeOfService = 11,
    HostTypeOfService = 12,
    AdminProhib = 13,
    HostPrecViol = 14,
    PrecCutOff = 15,
}

impl IcmpCodeUnreach {
    fn from_u8(val: u8) -> Result<Self> {
        match val {
            x if x == Self::Network           as u8 => Ok(Self::Network),
            x if x == Self::Host              as u8 => Ok(Self::Host),
            x if x == Self::Protocol          as u8 => Ok(Self::Protocol),
            x if x == Self::Port              as u8 => Ok(Self::Port),
            x if x == Self::FragNeeded        as u8 => Ok(Self::FragNeeded),
            x if x == Self::SourceRoute       as u8 => Ok(Self::SourceRoute),
            x if x == Self::DestNetUnknown    as u8 => Ok(Self::DestNetUnknown),
            x if x == Self::DestHostUnknown   as u8 => Ok(Self::DestHostUnknown),
            x if x == Self::SourceHostIso     as u8 => Ok(Self::SourceHostIso),
            x if x == Self::DestAdminProhib   as u8 => Ok(Self::DestAdminProhib),
            x if x == Self::HostAdminProhib   as u8 => Ok(Self::HostAdminProhib),
            x if x == Self::NetTypeOfService  as u8 => Ok(Self::NetTypeOfService),
            x if x == Self::HostTypeOfService as u8 => Ok(Self::HostTypeOfService),
            x if x == Self::AdminProhib       as u8 => Ok(Self::AdminProhib),
            x if x == Self::HostPrecViol      as u8 => Ok(Self::HostPrecViol),
            x if x == Self::PrecCutOff        as u8 => Ok(Self::PrecCutOff),
            _ => Err(anyhow::Error::msg(format!("bad code {}", val))),
        }
    }
}

#[derive(Clone, Debug, Copy)]
enum IcmpCodeTimeEx {
    Ttl = 0,
    FragmentReassmbly = 1,
}

#[derive(Clone, Debug, Copy)]
enum ProbeResult {
    Timeout,
    Response {
        from: IpAddr,
        error: Errno,
        terminal: bool,

        print_unreach: Option<IcmpCodeUnreach>,

        latency_ms: f64,
    },
}

impl ProbeResult {
    fn from_ipv4(ee: &libc::sock_extended_err, addr: Option<libc::sockaddr_in>, duration: Duration) -> Result<Self> {
        let addr = addr.map(|s| IpAddr::V4(Ipv4Addr(s.sin_addr)))
            .ok_or(anyhow::Error::msg("missing origin"))?;
        Ok(Self::from_ip(ee, addr, duration))
    }

    fn from_ip(ee: &libc::sock_extended_err, from: IpAddr, duration: Duration) -> Self {
        let mut terminal = false;
        let mut print_unreach = None;

        if ee.ee_type == IcmpType::Unreachable as _ {
            print_unreach = IcmpCodeUnreach::from_u8(ee.ee_code).ok();

            match print_unreach {
                Some(IcmpCodeUnreach::Port) | Some(IcmpCodeUnreach::AdminProhib) => {
                    terminal = true;
                }
                _ => (),
            }
        } else if ee.ee_type == IcmpType::TimeExceeded as _ {
            if ee.ee_code != IcmpCodeTimeEx::Ttl as _ {
                println!(">> Time exceeded (code {}) from {}", ee.ee_code, from);
            }
        } else {
            println!("Unexpected Icmp type {} (code {}) from {}", ee.ee_type, ee.ee_code, from);
        }

        let latency_ms = (duration.as_nanos() as f64) / 1_000_000.;

        ProbeResult::Response {
            from,
            error: Errno::from_i32(ee.ee_errno as _),
            terminal,
            print_unreach,
            latency_ms,
        }
    }
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

// Get the average latency of responses at some TTL, if there are any.
fn avg_latency_ms(state: &State, ttl: u8) -> Option<f64> {
    let results = &state.results[ttl as usize];
    let mut divisor = 0;
    let mut dividend = 0.;

    for r in results {
        match r {
            ProbeResult::Timeout => (),
            ProbeResult::Response { latency_ms, .. } => {
                divisor += 1;
                dividend += *latency_ms;
            }
        }
    }

    if divisor == 0 {
        return None;
    }
    return Some(dividend / f64::from(divisor));
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

fn print_unreachable(u: IcmpCodeUnreach) {
    let s = match u {
        IcmpCodeUnreach::Network => Some("N".into()),
        IcmpCodeUnreach::Host => Some("H".into()),
        IcmpCodeUnreach::Protocol => Some("P".into()),
        IcmpCodeUnreach::SourceRoute => Some("S".into()),
        IcmpCodeUnreach::FragNeeded => Some("F".into()),
        IcmpCodeUnreach::AdminProhib => Some("X".into()),
        IcmpCodeUnreach::HostPrecViol => Some("V".into()),
        IcmpCodeUnreach::PrecCutOff => Some("C".into()),

        // Expected, for the final packet.
        IcmpCodeUnreach::Port => None,

        _ => Some(format!("{}", u as u8)),
    };

    if let Some(anno) = s {
        print!(" !{}", anno);
    }
}

// Print probe results for a single hop (one line)
fn print_result(ttl: u8, results: &Vec<ProbeResult>) {
    print!(" {} ", ttl);

    let mut prev_from = None;
    for r in results {
        match r {
            ProbeResult::Timeout => {
                print!(" *");
            }
            ProbeResult::Response { from, print_unreach, latency_ms, .. } => {
                // Coalesce responses from the same IP at the same TTL greedily.  If the sequence
                // is A -> B -> A, we print all three times.  Normal traceroute is also this dumb,
                // it's ok.
                if prev_from != Some(from) {
                    print!(" {}", from);
                    prev_from = Some(from);
                }
                if *latency_ms > 1000. {
                    let latency_s = latency_ms / 1000.;
                    print!("  {:.3} s", latency_s);
                } else {
                    print!("  {:.3} ms", latency_ms);
                }
                if let Some(anno) = *print_unreach {
                    print_unreachable(anno);
                }
            }
        }
    }
    println!();
}

// Print any complete result lines available (in order)
fn print_results(config: &Config, state: &mut State, probe_ttl: u8) {
    for (ttl, results) in state.results.iter().enumerate().skip(probe_ttl as _) {
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
}

// Shared packet buffer reused between individual processing.
struct RecvCache {
    buf: Vec<u8>,
    cmsg_space: Vec<u8>,
}

// Process an fd.  If we should stop polling this fd, returns Ok(true).
fn process_ready_fd(config: &Config, state: &mut State, probe_idx: usize, buf: &mut RecvCache) -> Result<bool> {
    let probe = &state.probes[probe_idx];
    let iovec = [IoVec::from_mut_slice(&mut buf.buf)];
    let msg = recvmsg(probe.socket, &iovec, Some(&mut buf.cmsg_space), MsgFlags::MSG_ERRQUEUE)?;

    let probe_duration = probe.start.unwrap().elapsed();

    let mut res = false;

    for cmsg in msg.cmsgs() {
        match cmsg {
            ControlMessageOwned::Ipv4RecvErr(ee, addr) => {
                state.results[probe.ttl as usize].push(
                    ProbeResult::from_ipv4(&ee, addr, probe_duration)?
                );
                res = true;
            }
            _ => {
                println!("Unexpected cmsg {:?}", cmsg);
            }
        }
    }

    if res {
        let probe_ttl = probe.ttl;
        print_results(config, state, probe_ttl);
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
    let config = Config {
        num_probes: 3,
        ttl_max: 12,
        port_lo: 33433,
    };
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
