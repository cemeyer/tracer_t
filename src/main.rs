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
use nix::poll::{self, PollFd, PollFlags};
use nix::sys::socket::{self, *};
use nix::sys::uio::IoVec;
use nix::unistd;

#[derive(Debug)]
struct Config {
    ttl_max: u8,
    num_probes: u32,
    port_lo: u16,

    // Max timeout, in seconds
    timo_max_s: f64,
    // Relative timeout scaler (to other responses from the same gateway)
    timo_here_mult: f64,
    // Relative timeout scaler (to subsequent gateway(s) in the path)
    timo_near_mult: f64,
}

// XXX: may be able to reduce number of sockets.
#[derive(Debug)]
struct Probe {
    socket: RawFd,
    ttl: u8,
    // These are initialized None, then set to Some() on ::fire().
    start: Option<Instant>,
    // Deadline can be updated to be sooner (here/near), but never later.
    deadline: Option<Instant>,
}

impl Drop for Probe {
    fn drop(&mut self) {
        unistd::close(self.socket).unwrap();
    }
}

impl Probe {
    fn new(target: &IpAddr, ttl: u8) -> Result<Self> {
        let ttl32 = i32::from(ttl);
        let socket = match target {
            IpAddr::V4(_) => {
                let socket = socket::socket(AddressFamily::Inet,
                                            SockType::Datagram,
                                            SockFlag::SOCK_NONBLOCK,
                                            None)?;
                setsockopt(socket, sockopt::Ipv4RecvErr, &true).unwrap();
                setsockopt(socket, sockopt::Ipv4Ttl, &ttl32).unwrap();
                socket
            }
            IpAddr::V6(_) => {
                let socket = socket::socket(AddressFamily::Inet6,
                                            SockType::Datagram,
                                            SockFlag::SOCK_NONBLOCK,
                                            None)?;
                setsockopt(socket, sockopt::Ipv6RecvErr, &true).unwrap();
                setsockopt(socket, sockopt::Ipv6Ttl, &ttl32).unwrap();
                socket
            }
        };
        Ok(Self {
            socket,
            ttl,
            start: None,
            deadline: None,
        })
    }

    fn fire(&mut self, config: &Config, dst: IpAddr) -> Result<()> {
        let dst = SockAddr::new_inet(InetAddr::new(dst, config.port_lo + self.ttl as u16));
        let start = Instant::now();
        self.deadline = Some(start + Duration::from_secs_f64(config.timo_max_s));
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

impl TryFrom<u8> for IcmpCodeUnreach {
    type Error = u8;

    fn try_from(val: u8) -> Result<Self, u8> {
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
            _ => Err(val),
        }
    }
}

impl IcmpCodeUnreach {
    fn from_v6_result(val: Result<Icmpv6CodeUnreach, u8>) -> Result<Self, u8> {
        match val {
            Ok(code) => Self::try_from(code),
            Err(int) => Err(int),
        }
    }
}

#[derive(Clone, Debug, Copy)]
enum IcmpCodeTimeEx {
    Ttl = 0,
    FragmentReassembly = 1,
}

impl TryFrom<u8> for IcmpCodeTimeEx {
    type Error = u8;

    fn try_from(val: u8) -> Result<Self, u8> {
        match val {
            x if x == Self::Ttl                as u8 => Ok(Self::Ttl),
            x if x == Self::FragmentReassembly as u8 => Ok(Self::FragmentReassembly),
            _ => Err(val),
        }
    }
}

// ipv6
#[derive(Clone, Debug, Copy)]
enum Icmpv6Type {
    Unreachable = 1,
    TimeExceeded = 3,
}

#[derive(Clone, Debug, Copy)]
enum Icmpv6CodeUnreach {
    NoRoute = 0,
    AdminProhib = 1,
    SourceScope = 2,
    Host = 3,
    Port = 4,
    SourcePolicy = 5,
    RejectRoute = 6,
    SourceRoute = 7,
}

impl TryFrom<u8> for Icmpv6CodeUnreach {
    type Error = u8;

    fn try_from(val: u8) -> Result<Self, u8> {
        match val {
            x if x == Self::NoRoute      as u8 => Ok(Self::NoRoute),
            x if x == Self::AdminProhib  as u8 => Ok(Self::AdminProhib),
            x if x == Self::SourceScope  as u8 => Ok(Self::SourceScope),
            x if x == Self::Host         as u8 => Ok(Self::Host),
            x if x == Self::Port         as u8 => Ok(Self::Port),
            x if x == Self::SourcePolicy as u8 => Ok(Self::SourcePolicy),
            x if x == Self::RejectRoute  as u8 => Ok(Self::RejectRoute),
            x if x == Self::SourceRoute  as u8 => Ok(Self::SourceRoute),
            _ => Err(val),
        }
    }
}

impl TryFrom<Icmpv6CodeUnreach> for IcmpCodeUnreach {
    type Error = u8;

    fn try_from(v6: Icmpv6CodeUnreach) -> Result<Self, u8> {
        match v6 {
            Icmpv6CodeUnreach::NoRoute      => Ok(Self::Network),
            Icmpv6CodeUnreach::AdminProhib  => Ok(Self::AdminProhib),
            Icmpv6CodeUnreach::Host         => Ok(Self::Host),
            Icmpv6CodeUnreach::Port         => Ok(Self::Port),
            Icmpv6CodeUnreach::SourceRoute  => Ok(Self::SourceRoute),
            _ => Err(v6 as u8),
        }
    }
}

type Icmpv6CodeTimeEx = IcmpCodeTimeEx;

// Common v4-v6 abstraction.  Not especially general, but good enough for traceroute.
enum Icmp {
    Unreachable(Result<IcmpCodeUnreach, u8>),
    TimeExceeded(Result<IcmpCodeTimeEx, u8>),
    Unrecognized(u8, u8),
}

impl Icmp {
    fn from_v4(type_: u8, code: u8) -> Self {
        if type_ == IcmpType::Unreachable as _ {
            Icmp::Unreachable(IcmpCodeUnreach::try_from(code))
        } else if type_ == IcmpType::TimeExceeded as _ {
            Icmp::TimeExceeded(IcmpCodeTimeEx::try_from(code))
        } else {
            Icmp::Unrecognized(type_, code)
        }
    }

    fn from_v6(type_: u8, code: u8) -> Self {
        if type_ == Icmpv6Type::Unreachable as _ {
            let code6 = Icmpv6CodeUnreach::try_from(code);
            Icmp::Unreachable(IcmpCodeUnreach::from_v6_result(code6))
        } else if type_ == Icmpv6Type::TimeExceeded as _ {
            Icmp::TimeExceeded(Icmpv6CodeTimeEx::try_from(code))
        } else {
            Icmp::Unrecognized(type_, code)
        }
    }
}

#[derive(Clone, Debug, Copy)]
enum ProbeResult {
    Timeout,
    Response {
        from: IpAddr,
        terminal: bool,

        print_unreach: Option<Result<IcmpCodeUnreach, u8>>,

        latency_ms: f64,
    },
}

impl ProbeResult {
    fn from_ipv4(ee: &libc::sock_extended_err, addr: Option<libc::sockaddr_in>, duration: Duration) -> Result<Self> {
        let addr = addr.map(|s| IpAddr::V4(Ipv4Addr(s.sin_addr)))
            .ok_or(anyhow::Error::msg("missing origin"))?;
        let icmp = Icmp::from_v4(ee.ee_type, ee.ee_code);
        Ok(Self::from_ip(icmp, addr, duration))
    }

    fn from_ipv6(ee: &libc::sock_extended_err, addr: Option<libc::sockaddr_in6>, duration: Duration) -> Result<Self> {
        let addr = addr.map(|s| IpAddr::V6(Ipv6Addr(s.sin6_addr)))
            .ok_or(anyhow::Error::msg("missing origin"))?;
        let icmp = Icmp::from_v6(ee.ee_type, ee.ee_code);
        Ok(Self::from_ip(icmp, addr, duration))
    }

    fn from_ip(icmp: Icmp, from: IpAddr, duration: Duration) -> Self {
        let mut terminal = false;
        let mut print_unreach = None;

        match icmp {
            Icmp::Unreachable(code) => {
                print_unreach = Some(code);

                match code {
                    Ok(IcmpCodeUnreach::Port) | Ok(IcmpCodeUnreach::AdminProhib) => {
                        terminal = true;
                    }
                    _ => (),
                }
            }
            Icmp::TimeExceeded(code) => {
                match code {
                    Ok(IcmpCodeTimeEx::Ttl) => (),
                    _ => {
                        println!(">> Time exceeded (code {:?}) from {}", code, from);
                    }
                }
            }
            Icmp::Unrecognized(type_, code) => {
                println!("Unexpected Icmp type {} (code {}) from {}", type_, code, from);
            }
        }

        let latency_ms = (duration.as_nanos() as f64) / 1_000_000.;

        ProbeResult::Response {
            from,
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
    // [ttl] -> best observed latency ("here")
    probe_lat_ms: Vec<Option<f64>>,
    // [ttl] -> best observed future gateway latency ("near")
    probe_near_lat_ms: Vec<Option<f64>>,
}

fn send_probes(config: &Config, state: &mut State, target: IpAddr) -> Result<()> {
    state.results.resize(usize::from(config.ttl_max) + 1, Vec::new());
    for ttl in 1..=config.ttl_max {
        for probe in 0..config.num_probes {
            state.probes.push(Probe::new(&target, ttl)?);
        }
    }

    for probe in state.probes.iter_mut() {
        probe.fire(config, target)?;
    }

    Ok(())
}

// Returns the nearest deadline, if any
fn update_probe_deadlines(config: &Config, state: &mut State) -> Option<Duration> {
    let now = Instant::now();
    let mut nearest_deadline = None;

    // Update deadlines against here/near factors
    for probe in state.probes.iter_mut() {
        let ttl = probe.ttl as usize;

        let mut timo_s = config.timo_max_s;

        // "here"
        if let Some(lat_ms) = state.probe_lat_ms[ttl] {
            let here_timo_s = lat_ms * config.timo_here_mult / 1_000.;
            if here_timo_s < timo_s {
                timo_s = here_timo_s;
            }
        }

        // "near"
        if let Some(lat_ms) = state.probe_near_lat_ms[ttl] {
            let near_timo_s = lat_ms * config.timo_near_mult / 1_000.;
            if near_timo_s < timo_s {
                timo_s = near_timo_s;
            }
        }

        let timo_deadline = probe.start.unwrap() + Duration::from_secs_f64(timo_s);
        if timo_deadline < probe.deadline.unwrap() {
            probe.deadline = Some(timo_deadline);
        }

        if probe.deadline.unwrap() > now {
            if let Some(cur_deadline) = nearest_deadline {
                use std::cmp::min;
                nearest_deadline = Some(min(cur_deadline, probe.deadline.unwrap()));
            } else {
                nearest_deadline = probe.deadline;
            }
        }
    }

    nearest_deadline.map(|i| i.duration_since(now))
}

fn process_stale_probes(config: &Config, state: &mut State) {
    let now = Instant::now();
    let mut i = 0;
    while i < state.probes.len() {
        if state.probes[i].deadline.unwrap() < now {
            let to_probe = state.probes.swap_remove(i);
            state.results[to_probe.ttl as usize].push(ProbeResult::Timeout);
            print_results(config, state, to_probe.ttl);
        } else {
            i += 1;
        }
    }
}

fn check_readiness(config: &Config, state: &mut State) -> Result<Vec<RawFd>> {
    // Check for stale probes and induce timeouts
    //  1. update deadlines against here/near factors
    let until_nearest_deadline = update_probe_deadlines(config, state);
    //  2. check for stale probes and cancel => result::timeout
    process_stale_probes(config, state);
    //  3. set poll timeout to that of nearest deadline, minus now.  min 1 to avoid spin
    let poll_timo = if let Some(duration) = until_nearest_deadline {
        let ms = duration.as_millis();
        if ms < 1 {
            1
        } else if let Ok(ms32) = i32::try_from(ms) {
            ms32
        } else {
            i32::MAX
        }
    } else {
        1
    };

    let mut pfds = state.probes.iter().map(|p| PollFd::new(p.socket, PollFlags::POLLIN)).collect::<Vec<_>>();
    let n = poll::poll(&mut pfds, poll_timo)?;

    let mut res = Vec::with_capacity(n as usize);
    for pfd in pfds.iter() {
        if !pfd.revents().unwrap().is_empty() {
            res.push(pfd.as_raw_fd());
        }
    }

    Ok(res)
}

fn print_unreachable(u: Result<IcmpCodeUnreach, u8>) {
    let s = match u {
        Ok(IcmpCodeUnreach::Network) => Some("N".into()),
        Ok(IcmpCodeUnreach::Host) => Some("H".into()),
        Ok(IcmpCodeUnreach::Protocol) => Some("P".into()),
        Ok(IcmpCodeUnreach::SourceRoute) => Some("S".into()),
        Ok(IcmpCodeUnreach::FragNeeded) => Some("F".into()),
        Ok(IcmpCodeUnreach::AdminProhib) => Some("X".into()),
        Ok(IcmpCodeUnreach::HostPrecViol) => Some("V".into()),
        Ok(IcmpCodeUnreach::PrecCutOff) => Some("C".into()),

        // Expected, for the final packet.
        Ok(IcmpCodeUnreach::Port) => None,

        Ok(v) => Some(format!("{}", v as u8)),
        Err(v) => Some(format!("{}", v as u8)),
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

fn update_observed_lats_from(state: &mut State, ttl: u8) {
    let ttl = usize::from(ttl);
    let lat = match state.results[ttl].last().unwrap() {
        ProbeResult::Response { latency_ms, .. } => *latency_ms,
        _ => { panic!("invariant"); }
    };

    if state.probe_lat_ms[ttl].unwrap_or(f64::INFINITY) > lat {
        state.probe_lat_ms[ttl] = Some(lat);

        for ttl_i in (1..ttl).rev() {
            if state.probe_near_lat_ms[ttl_i].unwrap_or(f64::INFINITY) > lat {
                state.probe_near_lat_ms[ttl_i] = Some(lat);
            } else {
                break;
            }
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
    let probe_ttl = probe.ttl;
    let iovec = [IoVec::from_mut_slice(&mut buf.buf)];
    let msg = recvmsg(probe.socket, &iovec, Some(&mut buf.cmsg_space), MsgFlags::MSG_ERRQUEUE)?;

    let probe_duration = probe.start.unwrap().elapsed();

    let mut res = false;

    for cmsg in msg.cmsgs() {
        match cmsg {
            ControlMessageOwned::Ipv4RecvErr(ee, addr) => {
                state.results[probe_ttl as usize].push(
                    ProbeResult::from_ipv4(&ee, addr, probe_duration)?
                );
                update_observed_lats_from(state, probe_ttl);
                res = true;
            }
            ControlMessageOwned::Ipv6RecvErr(ee, addr) => {
                state.results[probe_ttl as usize].push(
                    ProbeResult::from_ipv6(&ee, addr, probe_duration)?
                );
                update_observed_lats_from(state, probe_ttl);
                res = true;
            }
            _ => {
                println!("Unexpected cmsg {:?}", cmsg);
            }
        }
    }

    if res {
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
        // sockaddr_in6 is bigger than sockaddr_in, so it works for either version.
        cmsg_space: nix::cmsg_space!(libc::sock_extended_err, libc::sockaddr_in6),
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

        // Same huge value as traceroute(8)
        timo_max_s: 5.,
        // Same defaults as traceroute(8)
        timo_here_mult: 3.,
        timo_near_mult: 10.,
    };
    let mut state = State {
        probes: Vec::new(),
        results: Vec::new(),
        last_printed: 0,
        was_terminal: false,

        probe_lat_ms: vec![None; usize::from(config.ttl_max) + 1],
        probe_near_lat_ms: vec![None; usize::from(config.ttl_max) + 1],
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
