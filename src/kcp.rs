use std::cmp;
use std::collections::VecDeque;
use std::io::{self, Write};
use std::ops::Deref;

use bytes::{LittleEndian, BufMut, ByteOrder, BytesMut};
use error::Error;

const KCP_RTO_NDL: u32 = 30;
const KCP_RTO_MIN: u32 = 100;
const KCP_RTO_DEF: u32 = 200;
const KCP_RTO_MAX: u32 = 60000;

const KCP_CMD_PUSH: u8 = 81;
const KCP_CMD_ACK: u8 = 82;
const KCP_CMD_WASK: u8 = 83;
const KCP_CMD_WINS: u8 = 84;

const KCP_ASK_SEND: u32 = 1;
const KCP_ASK_TELL: u32 = 2;

const KCP_WND_SND: u16 = 32;
const KCP_WND_RCV: u16 = 32;

const KCP_MTU_DEF: usize = 1400;
//const KCP_ACK_FAST: u32 = 3;

const KCP_INTERVAL: u32 = 100;
const KCP_OVERHEAD: usize = 24;
//const KCP_DEADLINK: u32 = 20;

const KCP_THRESH_INIT: u16 = 2;
const KCP_THRESH_MIN: u16 = 2;

const KCP_PROBE_INIT: u32 = 7000;
const KCP_PROBE_LIMIT: u32 = 120000;

pub fn get_conv(buf: &[u8]) -> u32 {
    LittleEndian::read_u32(buf)
}

#[inline]
fn bound(lower: u32, v: u32, upper: u32) -> u32 {
    cmp::min(cmp::max(lower, v), upper)
}

#[inline]
fn timediff(later: u32, earlier: u32) -> i32 {
    later as i32 - earlier as i32
}

#[derive(Default, Clone, Debug)]
struct KcpSegment {
    conv: u32,
    cmd: u8,
    frg: u8,
    wnd: u16,
    ts: u32,
    sn: u32,
    una: u32,
    resendts: u32,
    rto: u32,
    fastack: u32,
    xmit: u32,
    data: Vec<u8>,
}

impl KcpSegment {
    fn new(capacity: usize) -> Self {
        KcpSegment {
            conv: 0,
            cmd: 0,
            frg: 0,
            wnd: 0,
            ts: 0,
            sn: 0,
            una: 0,
            resendts: 0,
            rto: 0,
            fastack: 0,
            xmit: 0,
            data: Vec::with_capacity(capacity),
        }
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32::<LittleEndian>(self.conv);
        buf.put(self.cmd);
        buf.put(self.frg);
        buf.put_u16::<LittleEndian>(self.wnd);
        buf.put_u32::<LittleEndian>(self.ts);
        buf.put_u32::<LittleEndian>(self.sn);
        buf.put_u32::<LittleEndian>(self.una);
        buf.put_u32::<LittleEndian>(self.data.len() as u32);
    }
}

#[derive(Default)]
pub struct Kcp<Output: Write> {
    conv: u32,
    mtu: usize,
    mss: u32,
    state: i32,

    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,

    ssthresh: u16,

    rx_rttval: u32,
    rx_srtt: u32,
    rx_rto: u32,
    rx_minrto: u32,

    snd_wnd: u16,
    rcv_wnd: u16,
    rmt_wnd: u16,
    cwnd: u16,
    probe: u32,

    current: u32,
    interval: u32,
    ts_flush: u32,
    xmit: u32,

    nodelay: bool,
    updated: bool,

    ts_probe: u32,
    probe_wait: u32,

    dead_link: u32,
    incr: u32,

    snd_queue: VecDeque<KcpSegment>,
    rcv_queue: VecDeque<KcpSegment>,
    snd_buf: VecDeque<KcpSegment>,
    rcv_buf: VecDeque<KcpSegment>,

    acklist: Vec<(u32, u32)>,
    ackblock: usize,
    buf: BytesMut,

    fastresend: u32,
    nocwnd: bool,
    stream: bool,

    output: Output,
}

impl<Output: Write> Kcp<Output> {
    pub fn new(conv: u32, output: Output) -> Self {
        Kcp {
            conv: conv,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            rx_rttval: 0,
            rx_srtt: 0,
            state: 0,
            cwnd: 0,
            probe: 0,
            current: 0,
            xmit: 0,
            nodelay: false,
            updated: false,
            ts_probe: 0,
            probe_wait: 0,
            dead_link: 0,
            incr: 0,
            fastresend: 0,
            nocwnd: false,
            stream: false,

            snd_wnd: KCP_WND_SND,
            rcv_wnd: KCP_WND_RCV,
            rmt_wnd: KCP_WND_RCV,
            mtu: KCP_MTU_DEF,
            mss: (KCP_MTU_DEF - KCP_OVERHEAD) as u32,
            buf: BytesMut::with_capacity((KCP_MTU_DEF + KCP_OVERHEAD) * 3),
            snd_queue: VecDeque::new(),
            rcv_queue: VecDeque::new(),
            snd_buf: VecDeque::new(),
            rcv_buf: VecDeque::new(),
            acklist: vec![],
            ackblock: 0,
            rx_rto: KCP_RTO_DEF,
            rx_minrto: KCP_RTO_MIN,
            interval: KCP_INTERVAL,
            ts_flush: KCP_INTERVAL,
            ssthresh: KCP_THRESH_INIT,
            output: output,
        }
    }

    pub fn peeksize(&self) -> io::Result<usize> {
        match self.rcv_queue.front() {
            Some(segment) => {
                if segment.frg == 0 {
                    return Ok(segment.data.len());
                } else if self.rcv_queue.len() < segment.frg as usize + 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        Error::UnexceptedEOF,
                    ));
                }

                let mut len = 0;

                for segment in &self.rcv_queue {
                    len += segment.data.len();
                    if segment.frg == 0 {
                        break;
                    }
                }

                Ok(len)
            }
            None => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                Error::RecvQueueEmpty,
            )),
        }
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut len = 0;

        if self.rcv_queue.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                Error::RecvQueueEmpty,
            ));
        }

        let peeksize = self.peeksize()?;

        if peeksize > buf.len() {
            return Err(io::Error::new(io::ErrorKind::Other, Error::UserBufTooSmall));
        }

        let recover = self.rcv_queue.len() >= self.rcv_wnd as usize;

        while let Some(segment) = self.rcv_queue.pop_front() {
            buf[len..segment.data.len()].copy_from_slice(&segment.data[..]);
            len += segment.data.len();
            if segment.frg == 0 {
                break;
            }

        }
        assert_eq!(len, peeksize);

        while let Some(segment) = self.rcv_buf.pop_front() {
            if segment.sn == self.rcv_nxt && self.rcv_queue.len() < self.rcv_wnd as usize {
                self.rcv_queue.push_back(segment);
                self.rcv_nxt += 1;
            } else {
                break;
            }
        }

        if recover && self.rcv_queue.len() < self.rcv_wnd as usize {
            self.probe |= KCP_ASK_TELL;
        }

        Ok(len)
    }

    pub fn send(&mut self, buf: &mut BytesMut) -> io::Result<usize> {
        let mut len = buf.len();
        let mut sent_size = 0;

        assert!(self.mss > 0);

        if self.stream {
            while let Some(old_segment) = self.snd_queue.pop_back() {
                if old_segment.data.len() < self.mss as usize {
                    let capacity = self.mss as usize - old_segment.data.len();
                    let extend = cmp::min(buf.len(), capacity);
                    let mut new_segment = KcpSegment::new(capacity);
                    new_segment.data.extend(old_segment.data);
                    new_segment.data.extend(buf.split_to(extend));
                    new_segment.frg = 0;
                    self.snd_queue.push_back(new_segment);
                    sent_size += extend;
                    len -= extend;
                }

                if len == 0 {
                    return Ok(1);
                }
            }
        }

        let count = if len <= self.mss as usize {
            1
        } else {
            (len + self.mss as usize - 1) / self.mss as usize
        };

        if count > 255 {
            return Err(io::Error::new(io::ErrorKind::Other, Error::UserBufTooBig));
        }

        for i in 0..count {
            let size = cmp::min(self.mss as usize, len);

            let mut new_segment = KcpSegment::new(size);

            if len > 0 {
                new_segment.data.extend(buf.split_to(size));
            }

            new_segment.frg = if self.stream {
                0
            } else {
                (count - i - 1) as u8
            };

            self.snd_queue.push_back(new_segment);
            sent_size += size;
            len -= size;
        }

        Ok(sent_size)
    }

    fn update_ack(&mut self, rtt: i32) {
        if self.rx_srtt == 0 {
            self.rx_srtt = rtt as u32;
            self.rx_rttval = rtt as u32 / 2;
        } else {
            let delta = (rtt - self.rx_srtt as i32).abs() as u32;
            self.rx_rttval = (3 * self.rx_rttval + delta) / 4;
            self.rx_srtt = (7 * self.rx_srtt + rtt as u32) / 8;
            if self.rx_srtt < 1 {
                self.rx_srtt = 1
            };
        }
        let rto = self.rx_srtt + cmp::max(self.interval, 4 * self.rx_rttval);
        self.rx_rto = bound(self.rx_minrto, rto, KCP_RTO_MAX);
    }

    fn shrink_buf(&mut self) {
        self.snd_una = self.snd_queue.front().map(|seg| seg.sn).unwrap_or_else(
            || self.snd_nxt,
        );
    }

    fn parse_ack(&mut self, sn: u32) {
        if timediff(sn, self.snd_una) >= 0 && timediff(sn, self.snd_nxt) <= 0 {
            for index in 0..self.snd_buf.len() {
                if sn == self.snd_buf[index].sn {
                    self.snd_buf.remove(index);
                    break;
                } else if sn < self.snd_buf[index].sn {
                    break;
                }
            }
        }
    }

    fn parse_una(&mut self, una: u32) {
        for index in 0..self.snd_buf.len() {
            if timediff(una, self.snd_buf[index].sn) > 0 {
                self.snd_buf.remove(index);
            } else {
                break;
            }
        }
    }

    fn parse_fastack(&mut self, sn: u32) {
        if sn >= self.snd_una && sn < self.snd_nxt {
            for seg in &mut self.snd_buf {
                if sn < seg.sn {
                    break;
                } else if sn != seg.sn {
                    seg.fastack += 1;
                }
            }
        }
    }

    fn ack_push(&mut self, sn: u32, ts: u32) {
        let new_size = self.acklist.len() + 1;
        if new_size > self.ackblock {
            let mut newblock = 8;
            while newblock < new_size {
                newblock <<= 1;
            }
            let mut new_acklist = Vec::with_capacity(newblock);
            for i in 0..self.acklist.len() {
                new_acklist.push(self.acklist[i]);
            }
            self.acklist = new_acklist;
            self.ackblock = newblock;
        }

        self.acklist.push((sn, ts));
    }

    fn parse_data(&mut self, new_segment: KcpSegment) {
        let sn = new_segment.sn;

        if timediff(sn, self.rcv_nxt + self.rcv_wnd as u32) < 0 && timediff(sn, self.rcv_nxt) >= 0 {
            let mut repeat = false;
            let mut new_index = 0;

            for (index, segment) in self.rcv_buf.iter().rev().enumerate() {
                if segment.sn == sn {
                    repeat = true;
                    break;
                } else if timediff(sn, segment.sn) > 0 {
                    break;
                }
                new_index = index;
            }

            if !repeat {
                let len = self.rcv_buf.len();
                self.rcv_buf.insert(len - new_index as usize, new_segment);
            }

            let mut index = 0;
            let mut nrcv_que = self.rcv_queue.len();

            for seg in &self.rcv_buf {
                if seg.sn == self.rcv_nxt && nrcv_que < self.rcv_wnd as usize {
                    nrcv_que += 1;
                    self.rcv_nxt += 1;
                    index += 1;
                } else {
                    break;
                }
            }

            if index > 0 {
                let new_rcv_buf = self.rcv_buf.split_off(index);
                self.rcv_queue.append(&mut self.rcv_buf);
                self.rcv_buf = new_rcv_buf;
            }
        }
    }

    pub fn input(&mut self, buf: &mut BytesMut) -> io::Result<()> {
        let mut flag = false;
        let mut max_ack = 0;

        if buf.len() < KCP_OVERHEAD {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                Error::InvaidSegmentSize(buf.len()),
            ));
        }

        while buf.len() >= KCP_OVERHEAD {
            let conv = LittleEndian::read_u32(buf.split_to(4).deref());
            if conv != self.conv {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    Error::ConvInconsistent(self.conv, conv),
                ));
            }

            let cmd = buf.split_to(1)[0];
            let frg = buf.split_to(1)[0];
            let wnd = LittleEndian::read_u16(buf.split_to(2).deref());
            let ts = LittleEndian::read_u32(buf.split_to(4).deref());
            let sn = LittleEndian::read_u32(buf.split_to(4).deref());
            let una = LittleEndian::read_u32(buf.split_to(4).deref());
            let len = LittleEndian::read_u32(buf.split_to(4).deref()) as usize;

            if len > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    Error::InvaidSegmentDataSize(len, buf.len()),
                ));
            }

            if cmd != KCP_CMD_PUSH && cmd != KCP_CMD_ACK && cmd != KCP_CMD_WASK &&
                cmd != KCP_CMD_WINS
            {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    Error::UnsupportCmd(cmd),
                ));
            }

            self.rmt_wnd = wnd;

            self.parse_una(una);
            self.shrink_buf();

            match cmd {
                KCP_CMD_ACK => {
                    let rtt = timediff(self.current, ts);
                    if rtt >= 0 {
                        self.update_ack(rtt);
                    }
                    self.parse_ack(sn);
                    self.shrink_buf();

                    if !flag {
                        max_ack = sn;
                        flag = true;
                    } else if timediff(sn, max_ack) > 0 {
                        max_ack = sn;
                    }
                }
                KCP_CMD_PUSH => {
                    if timediff(sn, self.rcv_nxt + self.rcv_wnd as u32) < 0 {
                        self.ack_push(sn, ts);
                        if timediff(sn, self.rcv_nxt) >= 0 {
                            let mut segment = KcpSegment::new(len as usize);
                            segment.conv = conv;
                            segment.cmd = cmd;
                            segment.frg = frg;
                            segment.wnd = wnd;
                            segment.ts = ts;
                            segment.sn = sn;
                            segment.una = una;

                            if len > 0 {
                                segment.data.extend(buf.split_to(len));
                            }

                            self.parse_data(segment);
                        }
                    }
                }
                KCP_CMD_WASK => {
                    self.probe |= KCP_ASK_TELL;
                }
                KCP_CMD_WINS => (),//do nothing,
                _ => panic!("should run here?"),
            }
        }

        if flag {
            self.parse_fastack(max_ack);
        }

        let una = self.snd_una;

        if timediff(self.snd_una, una) > 0 && self.cwnd < self.rmt_wnd {
            let mss = self.mss;
            if self.cwnd < self.ssthresh {
                self.cwnd += 1;
                self.incr += mss;
            } else {
                if self.incr < mss {
                    self.incr = mss;
                }
                self.incr += (mss * mss) / self.incr + (mss / 16);
                if (self.cwnd + 1) as u32 * mss <= self.incr {
                    self.cwnd += 1;
                }
            }

            if self.cwnd > self.rmt_wnd {
                self.cwnd = self.rmt_wnd;
                self.incr = self.rmt_wnd as u32 * mss;
            }
        }

        Ok(())
    }

    fn wnd_unused(&self) -> u16 {
        if self.rcv_queue.len() < self.rcv_wnd as usize {
            self.rcv_wnd - self.rcv_queue.len() as u16
        } else {
            0
        }
    }

    fn flush_ack(&mut self, segment: &mut KcpSegment) -> io::Result<()> {
        // flush acknowledges
        while !self.acklist.is_empty() {
            let (sn, ts) = self.acklist.remove(0);
            if self.buf.len() + KCP_OVERHEAD > self.mtu as usize {
                self.output.write_all(self.buf.take().deref())?;
            }
            segment.sn = sn;
            segment.ts = ts;
            segment.encode(&mut self.buf);
        }

        Ok(())
    }

    fn probe_wnd_size(&mut self) {
        // probe window size (if remote window size equals zero)
        if self.rmt_wnd == 0 {
            if self.probe_wait == 0 {
                self.probe_wait = KCP_PROBE_INIT;
                self.ts_probe = self.current + self.probe_wait;
            } else if timediff(self.current, self.ts_probe) >= 0 {
                if self.probe_wait < KCP_PROBE_INIT {
                    self.probe_wait = KCP_PROBE_INIT;
                }
                self.probe_wait += self.probe_wait / 2;
                if self.probe_wait > KCP_PROBE_LIMIT {
                    self.probe_wait = KCP_PROBE_LIMIT;
                }
                self.ts_probe = self.current + self.probe_wait;
                self.probe |= KCP_ASK_SEND;
            }
        } else {
            self.ts_probe = 0;
            self.probe_wait = 0;
        }
    }

    fn flush_probe_commands(&mut self, segment: &mut KcpSegment) -> io::Result<()> {
        // flush window probing commands
        if self.probe & KCP_ASK_SEND != 0 {
            segment.cmd = KCP_CMD_WASK;
            if self.buf.len() + KCP_OVERHEAD > self.mtu as usize {
                self.output.write_all(self.buf.take().deref())?;
            }
            segment.encode(&mut self.buf);
        }

        // flush window probing commands
        if self.probe & KCP_ASK_TELL != 0 {
            segment.cmd = KCP_CMD_WINS;
            if self.buf.len() + KCP_OVERHEAD > self.mtu as usize {
                self.output.write_all(self.buf.take().deref())?;
            }
            segment.encode(&mut self.buf);
        }

        self.probe = 0;

        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        if !self.updated {
            return Err(io::Error::new(io::ErrorKind::Other, Error::NeedUpdate));
        }

        let mut segment = KcpSegment::default();
        segment.conv = self.conv;
        segment.cmd = KCP_CMD_ACK;
        segment.wnd = self.wnd_unused();
        segment.una = self.rcv_nxt;

        self.flush_ack(&mut segment)?;
        self.probe_wnd_size();
        self.flush_probe_commands(&mut segment)?;

        // calculate window size
        let mut cwnd = cmp::min(self.snd_wnd, self.rmt_wnd);
        if !self.nocwnd {
            cwnd = cmp::min(self.cwnd, cwnd);
        }

        // move data from snd_queue to snd_buf
        while timediff(self.snd_nxt, self.snd_una + cwnd as u32) < 0 {
            match self.snd_queue.pop_front() {
                Some(mut new_segment) => {
                    new_segment.conv = self.conv;
                    new_segment.cmd = KCP_CMD_PUSH;
                    new_segment.wnd = segment.wnd;
                    new_segment.ts = self.current;
                    new_segment.sn = self.snd_nxt;
                    self.snd_nxt += 1;
                    new_segment.una = self.rcv_nxt;
                    new_segment.resendts = self.current;
                    new_segment.rto = self.rx_rto;
                    new_segment.fastack = 0;
                    new_segment.xmit = 0;
                    self.snd_buf.push_back(new_segment);

                }
                None => break,
            }
        }

        // calculate resent
        let resent = if self.fastresend > 0 {
            self.fastresend
        } else {
            u32::max_value()
        };

        let rtomin = if !self.nodelay { self.rx_rto >> 3 } else { 0 };

        let mut lost = false;
        let mut change = 0;

        for snd_segment in &mut self.snd_buf {
            let mut need_send = false;

            if snd_segment.xmit == 0 {
                need_send = true;
                snd_segment.xmit += 1;
                snd_segment.rto = self.rx_rto;
                snd_segment.resendts = self.current + snd_segment.rto + rtomin;
            } else if timediff(self.current, snd_segment.resendts) >= 0 {
                need_send = true;
                snd_segment.xmit += 1;
                self.xmit += 1;
                if !self.nodelay {
                    snd_segment.rto += self.rx_rto;
                } else {
                    snd_segment.rto += self.rx_rto / 2;
                }
                snd_segment.resendts = self.current + snd_segment.rto;
                lost = true;
            } else if snd_segment.fastack >= resent {
                need_send = true;
                snd_segment.xmit += 1;
                snd_segment.fastack = 0;
                snd_segment.resendts = self.current + snd_segment.rto;
                change += 1;
            }

            if need_send {
                snd_segment.ts = self.current;
                snd_segment.wnd = segment.wnd;
                snd_segment.una = self.rcv_nxt;

                let need = KCP_OVERHEAD + snd_segment.data.len();

                if self.buf.len() + need > self.mtu as usize {
                    self.output.write_all(self.buf.take().deref())?;
                }

                snd_segment.encode(&mut self.buf);

                if !snd_segment.data.is_empty() {
                    self.buf.extend_from_slice(snd_segment.data.deref());
                }

                if snd_segment.xmit >= self.dead_link {
                    self.state = -1;
                }
            }
        }

        if !self.buf.is_empty() {
            self.output.write_all(self.buf.take().deref())?;
        }

        // update ssthresh
        if change > 0 {
            let inflight = self.snd_nxt - self.snd_una;
            self.ssthresh = inflight as u16 / 2;
            if self.ssthresh < KCP_THRESH_MIN {

                self.ssthresh = KCP_THRESH_MIN;
            }
            self.cwnd = self.ssthresh + resent as u16;
            self.incr = self.cwnd as u32 * self.mss;
        }

        if lost {
            self.ssthresh = cwnd / 2;
            if self.ssthresh < KCP_THRESH_MIN {

                self.ssthresh = KCP_THRESH_MIN;
            }
            self.cwnd = 1;
            self.incr = self.mss;
        }

        if self.cwnd < 1 {
            self.cwnd = 1;
            self.incr = self.mss;
        }

        Ok(())
    }

    pub fn update(&mut self, current: u32) -> io::Result<()> {
        self.current = current;

        if !self.updated {
            self.updated = true;
            self.ts_flush = self.current;
        }

        let mut slap = timediff(self.current, self.ts_flush);

        if slap >= 10000 || slap < -10000 {
            self.ts_flush = self.current;
            slap = 0;
        }

        if slap >= 0 {
            self.ts_flush += self.interval;
            if timediff(self.current, self.ts_flush) >= 0 {
                self.ts_flush = self.current + self.interval;
            }
            self.flush()?;
        }

        Ok(())
    }

    pub fn check(&self, current: u32) -> u32 {
        if !self.updated {
            return 0;
        }

        let mut ts_flush = self.ts_flush;
        let mut tm_packet = u32::max_value();

        if timediff(current, ts_flush) >= 10000 || timediff(current, ts_flush) < -10000 {
            ts_flush = current;
        }

        if timediff(current, ts_flush) >= 0 {
            return 0;
        }

        let tm_flush = timediff(ts_flush, current) as u32;
        for seg in &self.snd_buf {
            let diff = timediff(seg.resendts, current);
            if diff <= 0 {
                return 0;
            }
            if (diff as u32) < tm_packet {
                tm_packet = diff as u32;
            }
        }

        cmp::min(cmp::min(tm_packet, tm_flush), self.interval)
    }

    pub fn setmtu(&mut self, mtu: usize) -> io::Result<()> {
        if mtu < 50 || mtu < KCP_OVERHEAD {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                Error::InvalidMtuSisze(mtu),
            ));
        }
        self.mtu = mtu;
        self.mss = (self.mtu - KCP_OVERHEAD) as u32;
        let size = self.buf.len();
        let new_size = (mtu + KCP_OVERHEAD) * 3;
        if size > new_size {
            self.buf.truncate((mtu + KCP_OVERHEAD) * 3);
        } else if size < new_size {
            self.buf.extend(vec![0; new_size - size]);
        }

        Ok(())
    }

    pub fn ikcp_interval(&mut self, mut interval: u32) {
        if interval > 5000 {
            interval = 5000;
        } else if interval < 10 {
            interval = 10;
        }
        self.interval = interval;
    }

    pub fn nodelay(&mut self, nodelay: u32, mut interval: i32, resend: i32, nc: bool) {
        if nodelay > 0 {
            self.nodelay = true;
            self.rx_minrto = KCP_RTO_NDL;
        } else {
            self.nodelay = false;
            self.rx_minrto = KCP_RTO_MIN;
        }

        if interval >= 0 {
            if interval > 5000 {
                interval = 5000;
            } else if interval < 10 {
                interval = 10;
            }

            self.interval = interval as u32;
        }

        if resend >= 0 {
            self.fastresend = resend as u32;
        }

        self.nocwnd = nc;
    }


    pub fn wndsize(&mut self, sndwnd: u16, rcvwnd: u16) {
        if sndwnd > 0 {
            self.snd_wnd = sndwnd as u16;
        }
        if rcvwnd > 0 {
            self.rcv_wnd = rcvwnd as u16;
        }
    }

    pub fn waitsnd(&self) -> usize {
        self.snd_buf.len() + self.snd_queue.len()
    }
}
