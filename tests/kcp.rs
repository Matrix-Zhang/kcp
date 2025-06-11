extern crate bytes;
extern crate env_logger;
extern crate kcp;
extern crate rand;
extern crate time;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Cursor, ErrorKind, Read, Write};
use std::rc::Rc;
use std::thread::sleep;
use std::time::Duration;

use bytes::buf::{Buf, BufMut};
use bytes::BytesMut;
use rand::Rng;
use kcp::Kcp;

#[derive(Debug)]
struct DelayPacket {
    buf: BytesMut,
    ts: u32,
}

impl DelayPacket {
    fn new(buf: BytesMut) -> DelayPacket {
        DelayPacket { buf, ts: 0 }
    }

    fn len(&self) -> usize {
        self.buf.len()
    }

    fn ts(&self) -> u32 {
        self.ts
    }

    fn set_ts(&mut self, ts: u32) {
        self.ts = ts;
    }

    fn reader(self) -> Cursor<BytesMut> {
        Cursor::new(self.buf)
    }
}

struct Random {
    seeds: Vec<u32>,
    size: usize,
}

impl Random {
    fn new(size: usize) -> Random {
        Random {
            seeds: vec![0u32; size],
            size: 0,
        }
    }

    fn random(&mut self) -> u32 {
        if self.seeds.is_empty() {
            return 0;
        }

        if self.size == 0 {
            for (i, e) in self.seeds.iter_mut().enumerate() {
                *e = i as u32;
            }
            self.size = self.seeds.len();
        }

        let i = rand::rng().random_range(0..self.size);
        let x = self.seeds[i];

        self.size -= 1;
        self.seeds[i] = self.seeds[self.size];

        x
    }
}

#[inline]
fn current() -> u32 {
    (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1000000) as u32
}

struct LatencySimulator {
    lostrate: u32,
    rttmin: u32,
    rttmax: u32,
    nmax: usize,
    tx1: u32,
    tx2: u32,
    current: u32,
    p12: VecDeque<DelayPacket>,
    p21: VecDeque<DelayPacket>,
    r12: Random,
    r21: Random,
}

impl LatencySimulator {
    fn new(lostrate: u32, rttmin: u32, rttmax: u32, nmax: usize) -> LatencySimulator {
        LatencySimulator {
            lostrate: lostrate / 2,
            rttmin: rttmin / 2,
            rttmax: rttmax / 2,
            nmax,
            tx1: 0,
            tx2: 0,
            current: crate::current(),
            p12: VecDeque::new(),
            p21: VecDeque::new(),
            r12: Random::new(100),
            r21: Random::new(100),
        }
    }

    fn send(&mut self, peer: u32, data: &[u8]) -> usize {
        // println!("[VNET] SEND {} {:?}", peer, data);
        if peer == 0 {
            self.tx1 += 1;

            if self.r12.random() < self.lostrate {
                return data.len();
            }
            if self.p12.len() >= self.nmax {
                return data.len();
            }
        } else {
            self.tx2 += 1;

            if self.r21.random() < self.lostrate {
                return data.len();
            }
            if self.p21.len() >= self.nmax {
                return data.len();
            }
        }

        let mut pkg = DelayPacket::new(BytesMut::from(data));
        self.current = crate::current();

        let mut delay = self.rttmin;
        if self.rttmax > self.rttmin {
            delay += rand::random::<u32>() % (self.rttmax - self.rttmin);
        }

        pkg.set_ts(self.current + delay);

        if peer == 0 {
            self.p12.push_back(pkg);
        } else {
            self.p21.push_back(pkg);
        }

        data.len()
    }

    fn recv(&mut self, peer: u32, data: &mut [u8]) -> io::Result<usize> {
        {
            let pkg = if peer == 0 {
                match self.p12.front() {
                    None => {
                        return Err(io::Error::new(ErrorKind::WouldBlock, "No packet yet"));
                    }
                    Some(pkg) => pkg,
                }
            } else {
                match self.p21.front() {
                    None => {
                        return Err(io::Error::new(ErrorKind::WouldBlock, "No packet yet"));
                    }
                    Some(pkg) => pkg,
                }
            };

            self.current = crate::current();
            if self.current < pkg.ts() {
                return Err(io::Error::new(ErrorKind::WouldBlock, "No packet yet"));
            }

            if data.len() < pkg.len() {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "Buffer is too small",
                ));
            }
        }

        let pkg = if peer == 0 {
            self.p12.pop_front().unwrap()
        } else {
            self.p21.pop_front().unwrap()
        };

        pkg.reader().read(data)
    }
}

struct KcpOutput {
    sim: Rc<RefCell<LatencySimulator>>,
    peer: u32,
}

impl Write for KcpOutput {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut sim = self.sim.borrow_mut();
        Ok(sim.send(self.peer, data))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
enum TestMode {
    Default,
    Normal,
    Fast,
}

fn run(mode: TestMode, msgcount: u32, lostrate: u32) {
    // Rtt 60ms ~ 125ms
    let vnet = LatencySimulator::new(lostrate, 60, 125, 1000);
    let vnet = Rc::new(RefCell::new(vnet));

    let mut kcp1 = Kcp::new(
        0x11223344,
        KcpOutput {
            sim: vnet.clone(),
            peer: 0,
        },
    );
    let mut kcp2 = Kcp::new(
        0x11223344,
        KcpOutput {
            sim: vnet.clone(),
            peer: 1,
        },
    );

    let mut current = crate::current();
    let mut slap = current + 20;
    let mut index = 0;
    let mut next = 0;
    let mut count = 0;
    let mut maxrtt = 0;

    // Set wnd size, average latency 200ms, 20ms per packet
    // Set max wnd to 128 considering packet lost and retry
    kcp1.set_wndsize(128, 128);
    kcp2.set_wndsize(128, 128);

    match mode {
        TestMode::Default => {
            kcp1.set_nodelay(false, 10, 0, false);
            kcp2.set_nodelay(false, 10, 0, false);
        }
        TestMode::Normal => {
            kcp1.set_nodelay(false, 10, 0, true);
            kcp2.set_nodelay(false, 10, 0, true);
        }
        TestMode::Fast => {
            kcp1.set_nodelay(true, 10, 2, true);
            kcp2.set_nodelay(true, 10, 2, true);

            kcp1.set_rx_minrto(10);
            kcp2.set_fast_resend(1);
        }
    }

    // let mut ts1 = ::current();

    let mut buf = [0u8; 2000];
    while next <= msgcount {
        sleep(Duration::from_millis(1));

        current = crate::current();
        kcp1.update(crate::current()).unwrap();
        kcp2.update(crate::current()).unwrap();

        // kcp1 send packet every 20ms
        while current >= slap {
            let mut buf = BytesMut::with_capacity(8);
            buf.put_u32_le(index);
            index += 1;
            buf.put_u32_le(current);

            kcp1.send(&buf).unwrap();
            // println!("SENT curr: {} {} {:?}", index, current, &buf[..]);

            slap += 20;
        }

        // vnet p1 -> p2
        loop {
            let mut vn = vnet.borrow_mut();
            match vn.recv(1, &mut buf) {
                Err(..) => break,
                Ok(n) => {
                    // println!("RECV kcp2 {:?}", &buf[..n]);
                    kcp2.input(&buf[..n]).unwrap();
                }
            }
        }

        // vnet p2 -> p1
        loop {
            let mut vn = vnet.borrow_mut();
            match vn.recv(0, &mut buf) {
                Err(..) => break,
                Ok(n) => {
                    // println!("RECV kcp1 {:?}", &buf[..n]);
                    kcp1.input(&buf[..n]).unwrap();
                }
            }
        }

        // kcp2 echos back
        loop {
            match kcp2.recv(&mut buf) {
                Err(..) => break,
                Ok(n) => {
                    // println!("ECHO kcp2 {:?}", &buf[..n]);
                    kcp2.send(&buf[..n]).unwrap();
                }
            }
        }

        // kcp1 checks response from kcp2
        loop {
            match kcp1.recv(&mut buf) {
                Err(..) => break,
                Ok(n) => {
                    let mut cur = Cursor::new(&buf[..n]);

                    let sn = cur.get_u32_le();
                    let ts = cur.get_u32_le();
                    // println!("[RECV] sn={} ts={}", sn, ts);
                    let rtt = current - ts;

                    if sn != next {
                        panic!(
                            "Received not continuously packet: sn {} <-> {}",
                            count, next
                        );
                    }

                    next += 1;
                    count += 1;

                    if rtt > maxrtt {
                        maxrtt = rtt;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kcp_default() {
        run(TestMode::Default, 1000, 10);
    }

    #[test]
    fn kcp_normal() {
        run(TestMode::Normal, 1000, 10);
    }

    #[test]
    fn kcp_fast() {
        run(TestMode::Fast, 1000, 10);
    }

    #[test]
    fn kcp_massive_lost_default() {
        run(TestMode::Default, 1000, 50);
    }

    #[test]
    fn kcp_massive_lost_normal() {
        run(TestMode::Normal, 1000, 50);
    }

    #[test]
    fn kcp_massive_lost_fast() {
        run(TestMode::Fast, 1000, 50);
    }
}
