# AF_PACKET bindings for Rust

[![Crates.io](https://img.shields.io/crates/v/af_packet.svg)](https://crates.io/crates/af_packet)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![af_packet](https://docs.rs/af_packet/badge.svg)](https://docs.rs/af_packet)

This library is intended to provide an efficient, safe, and ergonomic way of reading raw packet data on an interface across multiple threads. Its primary intended use is for network security and monitoring applications, in conjunction with crates like `nom` (https://github.com/Geal/nom) to build protocol decoders and more complex analysis engines.

## A multi-threaded raw receiver in ~30 lines of code

The Linux kernel even provides flow balancing based on a hashed tuple so threads do not need to communicate with eachother to do flow reassembly

```rust
extern crate af_packet;
extern crate num_cpus;

use std::env;
use std::thread;

fn main() {
    let args: Vec<String> = env::args().collect();

    for _ in 0..num_cpus::get() {
        let interface = args[1].clone();
        thread::spawn(move || {
            let mut ring = af_packet::Ring::from_if_name(&interface).unwrap();
            loop {
                println!(
                    "Ring {} on {} has received {} packets and dropped {}",
                    ring.fd, ring.if_name, ring.packets, ring.drops
                );
                let mut block = ring.get_block();
                for _packet in block.get_raw_packets() {
                    //do something
                }
                block.mark_as_consumed();
            }
        });
    }
    loop {
        thread::sleep_ms(1000);
    }
}
```

*Based on work by Tom Karpiniec (http://thomask.sdf.org/blog/2017/09/01/layer-2-raw-sockets-on-rustlinux.html) and Herman Radtke (http://hermanradtke.com/2016/03/17/unions-rust-ffi.html)*
