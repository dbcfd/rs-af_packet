extern crate libc;

use std::io::{self, Error, ErrorKind};
use std::mem;

use libc::{setsockopt, getsockopt, recvfrom, socket, sockaddr, c_void, c_short, c_int, c_char, c_ulong, AF_PACKET, SOCK_RAW, SOL_SOCKET};

const ETH_P_ALL: u16 = 0x0003;
const PACKET_RX_RING: i32 = 5;

const SIOCGIFFLAGS: c_ulong = 0x00008913;
const SIOCSIFFLAGS: c_ulong = 0x00008914;

const IFF_PROMISC: c_ulong = 1<<8;

const IFNAMESIZE: usize = 16;
const IFREQUNIONSIZE: usize = 24;

/*
struct sockaddr {
    unsigned short sa_family;   // address family, AF_xxx
    char           sa_data[14]; // 14 bytes of protocol address
};

struct ifmap {
    unsigned long   mem_start;
    unsigned long   mem_end;
    unsigned short  base_addr;
    unsigned char   irq;
    unsigned char   dma;
    unsigned char   port;
};

struct ifreq {
    char ifr_name[IFNAMSIZ]; /* Interface name */
    union {
        struct sockaddr ifr_addr;
        struct sockaddr ifr_dstaddr;
        struct sockaddr ifr_broadaddr;
        struct sockaddr ifr_netmask;
        struct sockaddr ifr_hwaddr;
        short           ifr_flags;
        int             ifr_ifindex;
        int             ifr_metric;
        int             ifr_mtu;
        struct ifmap    ifr_map;
        char            ifr_slave[IFNAMSIZ];
        char            ifr_newname[IFNAMSIZ];
        char           *ifr_data;
    };
};
*/

#[derive(Clone, Debug)]
#[repr(C)]
struct IfReqUnion {
    data: [u8; IFREQUNIONSIZE],
}


impl Default for IfReqUnion {
    fn default() -> IfReqUnion {
        IfReqUnion { data: [0; IFREQUNIONSIZE] }
    }
}

impl IfReqUnion {
    fn as_sockaddr(&self) -> sockaddr {
        let mut s = sockaddr {
            sa_family: u16::from_be((self.data[0] as u16) << 8 | (self.data[1] as u16)),
            sa_data: [0; 14],
        };

        // basically a memcpy
        for (i, b) in self.data[2..16].iter().enumerate() {
            s.sa_data[i] = *b as i8;
        }

        s
    }

    fn as_int(&self) -> c_int {
        c_int::from_be((self.data[0] as c_int) << 24 |
                       (self.data[1] as c_int) << 16 |
                       (self.data[2] as c_int) <<  8 |
                       (self.data[3] as c_int))
    }

    fn as_short(&self) -> c_short {
        c_short::from_be((self.data[0] as c_short) << 8 |
                         (self.data[1] as c_short))
    }

    pub fn from_int(i: c_int) -> IfReqUnion {
        let mut union = IfReqUnion::default();
        let bytes: [u8;4] = unsafe { mem::transmute(i) };
        union.data[0] = bytes[0];
        union.data[1] = bytes[1];
        union.data[2] = bytes[2];
        union.data[3] = bytes[3];
        union
    }

    pub fn from_short(i: c_short) -> IfReqUnion {
        let mut union = IfReqUnion::default();
        let bytes: [u8;2] = unsafe { mem::transmute(i) };
        union.data[0] = bytes[0];
        union.data[1] = bytes[1];
        union
    }
}


#[derive(Clone, Debug)]
#[repr(C)]
pub struct IfReq {
    ifr_name: [c_char; IFNAMESIZE],
    union: IfReqUnion,
}

impl IfReq {
    ///
    /// Create an interface request struct with the interface name set
    ///
    pub fn with_if_name(if_name: &str) -> io::Result<IfReq> {
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

    pub fn ifr_hwaddr(&self) -> sockaddr {
        self.union.as_sockaddr()
    }

    pub fn ifr_dstaddr(&self) -> sockaddr {
        self.union.as_sockaddr()
    }

    pub fn ifr_broadaddr(&self) -> sockaddr {
        self.union.as_sockaddr()
    }

    pub fn ifr_ifindex(&self) -> c_int {
        self.union.as_int()
    }

    pub fn ifr_media(&self) -> c_int {
        self.union.as_int()
    }

    pub fn ifr_flags(&self) -> c_short {
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

extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, ifreq: *mut IfReq) -> c_int;
}


/// ioctl operations on a hardware interface
pub struct HwIf {
    if_name: String,
    pub fd: i32
}

impl HwIf {
    /// Create new hardware interface instance
    ///
    /// The interface name is something like `eth0`.
    pub fn new<S>(if_name: S) -> HwIf where S: Into<String> {
        let fd = unsafe { socket(AF_PACKET,
                             SOCK_RAW,
                             ETH_P_ALL.to_be() as i32,
                             ) };
        HwIf {
            if_name: if_name.into(),
            fd: fd
        }
    }

    fn get_flags(&self) -> io::Result<IfReq> {
        let if_req = try!(self.ioctl(SIOCGIFFLAGS, IfReq::with_if_name(&self.if_name).unwrap()));
        println!("GET {:?}", if_req);
        Ok(if_req)
    }

    fn set_flag(&mut self, flag: c_ulong) -> io::Result<c_int> {
        let flags = &self.get_flags().unwrap().ifr_flags();
        let new_flags = flags | flag as i16;
        let mut if_req = IfReq::with_if_name(&self.if_name).unwrap();
        if_req.union.data = IfReqUnion::from_short(new_flags).data;
        println!("SET {:?} -> {:?}", flags, new_flags);
        println!("SET {:?}", if_req);
        try!(self.ioctl(SIOCSIFFLAGS, if_req));
        Ok(0)
    }

    pub fn set_promisc(&mut self) -> io::Result<c_int> {
        self.set_flag(IFF_PROMISC)
    }

    fn ioctl(&self, ident: c_ulong, if_req: IfReq) -> io::Result<IfReq> {
        let mut req: Box<IfReq> = Box::new(if_req);

        let result = unsafe { ioctl(self.fd, ident, &mut *req) };

        if result == -1 {
            return Err(Error::last_os_error());
        }

        Ok(*req)
    }

/*    pub fn get_rx_ring(&mut self) {

        unsafe {
            setsockopt(self.fd, SOL_SOCKET, PACKET_RX_RING);
        }
    }

    pub fn get_rx_statistics(&mut self) {
        let mut optval: [u8; 32] = [0; 32];
        let mut optlen: u32 = 0;
        getsockopt(self.fd, SOL_SOCKET, PACKET_STATISTICS, &mut optval, &mut optlen);
    }
    */

    pub fn recv_single_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        let len: isize;
        let mut sock = sockaddr { sa_data: [0; 14], sa_family: 0 };
        unsafe {
            len = match recvfrom(self.fd, // file descriptor
                                    buf.as_mut_ptr() as *mut c_void, // pointer to buffer for frame content
                                    buf.len(), // frame content buffer length
                                    0,
                                    &mut sock,
                                    &mut 0) { // sender address buffer length
                -1 => {
                    return Err(io::Error::last_os_error());
                },
                len => len
            };
        }
        // Return the number of valid bytes that were placed in the buffer
        Ok(len as usize)
    }
}
