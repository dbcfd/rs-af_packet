extern crate libc;

use std::ffi::CString;
use std::io::{self, Error, ErrorKind};
use std::mem;

use libc::{bind, c_char, c_int, c_short, c_ulong, c_void, getpid, getsockopt, if_nametoindex,
           ioctl, mmap, poll, pollfd, setsockopt, sockaddr, sockaddr_ll, socket, socklen_t,
           AF_PACKET, ETH_ALEN, ETH_P_ALL, ETH_P_IP, IFF_PROMISC, MAP_LOCKED, MAP_NORESERVE,
           MAP_SHARED, PF_PACKET, POLLERR, POLLIN, PROT_READ, PROT_WRITE, SOCK_RAW, SOL_PACKET};

const PACKET_RX_RING: c_int = 5;
const PACKET_STATISTICS: c_int = 6;
const PACKET_VERSION: c_int = 10;
const PACKET_FANOUT: c_int = 18;

//const PACKET_FANOUT_HASH: c_int = 0;
const PACKET_FANOUT_LB: c_int = 1;

const PACKET_HOST: u8 = 0;
const PACKET_BROADCAST: u8 = 1;
const PACKET_MULTICAST: u8 = 2;
const PACKET_OTHERHOST: u8 = 3;
const PACKET_OUTGOING: u8 = 4;

const TP_STATUS_KERNEL: u8 = 0;
const TP_STATUS_USER: u8 = 1;
//const TP_STATUS_COPY: u8 = 1 << 1;
//const TP_STATUS_LOSING: u8 = 1 << 2;
//const TP_STATUS_CSUMNOTREADY: u8 = 1 << 3;
//const TP_STATUS_CSUM_VALID: u8 = 1 << 7;

const TPACKET_V3: c_int = 2;

const SIOCGIFFLAGS: c_ulong = 35091; //0x00008913;
const SIOCSIFFLAGS: c_ulong = 35092; //0x00008914;

const IFNAMESIZE: usize = 16;
const IFREQUNIONSIZE: usize = 24;

//const TP_FT_REQ_FILL_RXHASH: c_int = 0x1;

const TP_BLK_STATUS_OFFSET: usize = 8;

#[derive(Clone, Debug)]
#[repr(C)]
struct IfReqUnion {
    data: [u8; IFREQUNIONSIZE],
}

impl Default for IfReqUnion {
    fn default() -> IfReqUnion {
        IfReqUnion {
            data: [0; IFREQUNIONSIZE],
        }
    }
}

impl IfReqUnion {
    fn as_short(&self) -> c_short {
        c_short::from_be((self.data[0] as c_short) << 8 | (self.data[1] as c_short))
    }

    fn from_short(i: c_short) -> IfReqUnion {
        let mut union = IfReqUnion::default();
        let bytes: [u8; 2] = unsafe { mem::transmute(i) };
        union.data[0] = bytes[0];
        union.data[1] = bytes[1];
        union
    }
}

#[derive(Clone, Debug)]
#[repr(C)]
struct IfReq {
    ifr_name: [c_char; IFNAMESIZE],
    union: IfReqUnion,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct TpacketStatsV3 {
    pub tp_packets: u8,
    pub tp_drops: u8,
    pub tp_freeze_q_cnt: u8,
}

impl IfReq {
    fn with_if_name(if_name: &str) -> io::Result<IfReq> {
        let mut if_req = IfReq::default();

        if if_name.len() >= if_req.ifr_name.len() {
            return Err(Error::new(ErrorKind::Other, "Interface name too long"));
        }

        // basically a memcpy
        for (a, c) in if_req.ifr_name.iter_mut().zip(if_name.bytes()) {
            *a = c as i8;
        }

        Ok(if_req)
    }

    fn ifr_flags(&self) -> c_short {
        self.union.as_short()
    }
}

impl Default for IfReq {
    fn default() -> IfReq {
        IfReq {
            ifr_name: [0; IFNAMESIZE],
            union: IfReqUnion::default(),
        }
    }
}

pub struct Ring {
    if_name: String,
    fd: c_int,
    mmap: Option<*mut u8>,
    opts: TpacketReq3,
}

#[derive(Clone, Debug)]
pub struct TpacketReq3 {
    tp_block_size: c_int,
    tp_block_nr: c_int,
    tp_frame_size: c_int,
    tp_frame_nr: c_int,
    tp_retire_blk_tov: c_int,
    tp_sizeof_priv: c_int,
    tp_feature_req_word: c_int,
}

#[derive(Clone, Debug)]
pub struct TpacketBlockDesc {
    version: u32,
    offset_to_priv: u32,
    hdr: TpacketBDHeader,
}

#[derive(Clone, Debug)]
pub struct TpacketBDHeader {
    block_status: u32,
    num_pkts: u32,
    offset_to_first_pkt: u32,
    blk_len: u32,
    seq_num: u64,
    ts_first_pkt: TpacketBDTS,
    ts_last_pkt: TpacketBDTS,
}

#[derive(Clone, Debug)]
pub struct TpacketBDTS {
    ts_sec: u32,
    ts_nsec: u32,
}

#[derive(Clone, Debug)]
pub struct Tpacket3Hdr {
    tp_next_offset: u32,
    tp_sec: u32,
    tp_nsec: u32,
    tp_snaplen: u32,
    tp_len: u32,
    tp_status: u32,
    tp_mac: u16,
    tp_net: u16,
}

#[derive(Debug)]
pub struct Block<'a> {
    block_desc: TpacketBlockDesc,
    packets: Vec<RawPacket<'a>>,
    raw_data: &'a mut [u8],
}

#[derive(Debug)]
pub struct RawPacket<'a> {
    tpacket3_hdr: Tpacket3Hdr,
    data: &'a [u8],
}

impl<'a> Block<'a> {
    #[inline]
    pub fn mark_as_consumed(&mut self) {
        //32 bits but doesn't seem like we need to zero more than one byte (perhaps only one bit even)
        self.raw_data[TP_BLK_STATUS_OFFSET] = TP_STATUS_KERNEL;
        //self.data[TP_BLK_STATUS_OFFSET + 1] = TP_STATUS_KERNEL;
        //self.data[TP_BLK_STATUS_OFFSET + 2] = TP_STATUS_KERNEL;
        //self.data[TP_BLK_STATUS_OFFSET + 3] = TP_STATUS_KERNEL;
    }

    #[inline]
    pub fn is_ready(&self) -> bool {
        (self.raw_data[TP_BLK_STATUS_OFFSET] & TP_STATUS_USER) != 0
    }

    #[inline]
    pub fn get_raw_packets(&self) -> Vec<RawPacket> {
        //standard block header is 48b

        let mut packets = Vec::<RawPacket>::new();
        let mut next_offset = 48;

        let count = self.block_desc.hdr.num_pkts;
        for x in 0..count {
            let this_offset = next_offset;
            let mut tpacket3_hdr = get_tpacket3_hdr(&self.raw_data[next_offset..]);
            if x < count - 1 {
                next_offset = this_offset + tpacket3_hdr.tp_next_offset as usize;
            } else {
                next_offset = self.raw_data.len();
                tpacket3_hdr.tp_next_offset = 0;
            }
            packets.push(RawPacket {
                tpacket3_hdr: tpacket3_hdr,
                data: &self.raw_data[this_offset..next_offset],
            });
        }

        packets
    }
}

impl Ring {
    pub fn from_if_name(if_name: &str) -> io::Result<Ring> {
        //this typecasting sucks :(
        let fd = unsafe { socket(PF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as i32) };
        if fd < 0 {
            return Err(Error::last_os_error());
        }

        //TODO these values are stupid and should be changed
        let opts = TpacketReq3 {
            tp_block_size: 32768,
            tp_block_nr: 10000,
            tp_frame_size: 2048,
            tp_frame_nr: 160000,
            tp_retire_blk_tov: 10,
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0 //TP_FT_REQ_FILL_RXHASH as c_int,
        };

        let mut ring = Ring {
            if_name: String::from(if_name),
            fd,
            mmap: None,
            opts,
        };

        ring.set_promisc()?;
        ring.set_tpacket_v3()?;
        ring.get_rx_ring()?;
        ring.mmap_rx_ring()?;
        ring.bind_rx_ring()?;
        ring.set_fanout()?;
        Ok(ring)
    }

    #[inline]
    pub fn get_block(&self) -> Block {
        loop {
            self.wait_for_block();
            //check all blocks in memory space
            for i in 0..self.opts.tp_block_nr {
                if let Some(mut block) = self.get_single_block(i) {
                    if block.is_ready() {
                        return block;
                    }
                }
            }
        }
    }

    fn get_flags(&self) -> io::Result<IfReq> {
        self.ioctl(SIOCGIFFLAGS, IfReq::with_if_name(&self.if_name)?)
    }

    fn set_flag(&mut self, flag: c_ulong) -> io::Result<()> {
        let flags = &self.get_flags()?.ifr_flags();
        let new_flags = flags | flag as c_short; //CHANGED
        let mut if_req = IfReq::with_if_name(&self.if_name)?;
        if_req.union.data = IfReqUnion::from_short(new_flags).data;
        self.ioctl(SIOCSIFFLAGS, if_req)?;
        Ok(())
    }

    pub fn set_promisc(&mut self) -> io::Result<()> {
        self.set_flag(IFF_PROMISC as u64)
    }

    fn ioctl(&self, ident: c_ulong, if_req: IfReq) -> io::Result<IfReq> {
        let mut req: Box<IfReq> = Box::new(if_req);
        match unsafe { ioctl(self.fd, ident, &mut *req) } {
            -1 => Err(Error::last_os_error()),
            _ => Ok(*req),
        }
    }

    fn set_tpacket_v3(&mut self) -> io::Result<()> {
        match unsafe {
            setsockopt(
                self.fd,
                SOL_PACKET,
                PACKET_VERSION,
                &mut TPACKET_V3 as *mut _ as *mut c_void,
                mem::size_of_val(&TPACKET_V3) as socklen_t,
            )
        } {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    fn get_rx_ring(&mut self) -> io::Result<()> {
        match unsafe {
            setsockopt(
                self.fd,
                SOL_PACKET,
                PACKET_RX_RING,
                &mut self.opts as *mut _ as *mut c_void,
                mem::size_of_val(&self.opts) as socklen_t,
            )
        } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    fn mmap_rx_ring(&mut self) -> io::Result<()> {
        match unsafe {
            mmap(
                std::ptr::null_mut(),
                (self.opts.tp_block_size * self.opts.tp_block_nr) as usize,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_LOCKED | MAP_NORESERVE,
                self.fd,
                0,
            )
        } as isize
        {
            -1 => Err(io::Error::last_os_error()),
            map => {
                self.mmap = Some(map as *mut u8);
                Ok(())
            }
        }
    }

    fn bind_rx_ring(&mut self) -> io::Result<()> {
        let name = CString::new(self.if_name.to_owned())?;
        let index = unsafe { if_nametoindex(name.as_ptr()) };

        let mut sa = sockaddr_ll {
            sll_family: AF_PACKET as u16,
            sll_protocol: ETH_P_IP.to_be() as u16,
            sll_ifindex: index as c_int,
            sll_hatype: 519,
            sll_pkttype: (PACKET_HOST | PACKET_BROADCAST | PACKET_MULTICAST | PACKET_OTHERHOST
                | PACKET_OUTGOING),
            sll_halen: ETH_ALEN as u8,
            sll_addr: [0; 8],
        };

        //get the size before we change the pointer type otherwise it won't be correct
        let size = mem::size_of_val(&sa);
        //TODO: see if there is another way to do this...
        let addr_ptr = unsafe { mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut sa) };

        match unsafe { bind(self.fd, addr_ptr, size as socklen_t) } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    fn set_fanout(&mut self) -> io::Result<()> {
        let fanout = (unsafe { getpid() } & 0xFFFF) | (PACKET_FANOUT_LB << 16);
        match unsafe {
            setsockopt(
                self.fd,
                SOL_PACKET,
                PACKET_FANOUT,
                &fanout as *const _ as *const c_void,
                mem::size_of_val(&fanout) as socklen_t,
            )
        } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    #[inline]
    pub fn get_rx_statistics(&self) -> Result<TpacketStatsV3, Error> {
        let mut optval = TpacketStatsV3 {
            tp_packets: 0,
            tp_drops: 0,
            tp_freeze_q_cnt: 0,
        };
        let mut optlen = mem::size_of_val(&optval) as socklen_t;
        let stats = unsafe {
            getsockopt(
                self.fd,
                SOL_PACKET,
                PACKET_STATISTICS,
                &mut optval as *mut _ as *mut c_void,
                &mut optlen,
            )
        };
        if stats > 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(optval)
    }

    #[inline]
    fn wait_for_block(&self) {
        let mut pfd = pollfd {
            fd: self.fd,
            events: POLLIN | POLLERR,
            revents: 0,
        };

        unsafe {
            poll(&mut pfd, 1, -1);
        }
    }

    #[inline]
    pub fn get_single_block<'a>(&self, count: i32) -> Option<Block<'a>> {
        //TODO: clean up all this typecasting
        let offset = count as isize * self.opts.tp_block_size as isize;
        let block = unsafe {
            std::slice::from_raw_parts_mut(
                self.mmap.unwrap().offset(offset),
                self.opts.tp_block_size as usize,
            )
        };

        let length = u32_from_bytes(&block[20..24]) as usize; //length of whole block including header
        if length == 0 {
            return None;
        }

        //TODO: clean up what we don't need here to save operations?
        //TODO: deal with alignment here? should only matter for seq_num on 32-bit systems
        let blk = Block {
            block_desc: TpacketBlockDesc {
                version: u32_from_bytes(&block[0..4]),
                offset_to_priv: u32_from_bytes(&block[4..8]),
                hdr: TpacketBDHeader {
                    block_status: u32_from_bytes(&block[8..12]),
                    num_pkts: u32_from_bytes(&block[12..16]),
                    offset_to_first_pkt: u32_from_bytes(&block[16..20]),
                    blk_len: length as u32,
                    seq_num: u64_from_bytes(&block[24..32]),
                    ts_first_pkt: TpacketBDTS {
                        ts_sec: u32_from_bytes(&block[32..36]),
                        ts_nsec: u32_from_bytes(&block[36..40]),
                    },
                    ts_last_pkt: TpacketBDTS {
                        ts_sec: u32_from_bytes(&block[40..44]),
                        ts_nsec: u32_from_bytes(&block[44..48]),
                    },
                },
            },
            packets: Vec::new(),
            raw_data: &mut block[..length],
        };

        Some(blk)
    }
}

#[inline]
fn get_tpacket3_hdr(data: &[u8]) -> Tpacket3Hdr {
    Tpacket3Hdr {
        tp_next_offset: u32_from_bytes(&data[0..4]),
        tp_sec: u32_from_bytes(&data[4..8]),
        tp_nsec: u32_from_bytes(&data[8..12]),
        tp_snaplen: u32_from_bytes(&data[12..16]),
        tp_len: u32_from_bytes(&data[16..20]),
        tp_status: u32_from_bytes(&data[20..24]),
        tp_mac: u16_from_bytes(&data[24..26]),
        tp_net: u16_from_bytes(&data[26..28]),
    }
}

//there is probably a better way to do this but for now this works and seems reasonably efficient
//TODO: make this generic
#[inline]
fn u64_from_bytes(input: &[u8]) -> u64 {
    let mut u64_bytes = [0u8; 8];
    u64_bytes.clone_from_slice(input);
    unsafe { mem::transmute(u64_bytes) }
}

#[inline]
fn u32_from_bytes(input: &[u8]) -> u32 {
    let mut u32_bytes = [0u8; 4];
    u32_bytes.clone_from_slice(input);
    unsafe { mem::transmute(u32_bytes) }
}

#[inline]
fn u16_from_bytes(input: &[u8]) -> u16 {
    let mut u16_bytes = [0u8; 2];
    u16_bytes.clone_from_slice(input);
    unsafe { mem::transmute(u16_bytes) }
}
