# AF_PACKET bindings for Rust

[![Crates.io](https://img.shields.io/crates/v/af_packet.svg)](https://crates.io/crates/af_packet)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![af_packet](https://docs.rs/af_packet/badge.svg)](https://docs.rs/af_packet)

This library is intended to provide an efficient, safe, and ergonomic way of reading raw packet data on an interface across multiple threads. Its primary intended use is for network security and monitoring applications, in conjunction with crates like `nom` (https://github.com/Geal/nom) to build protocol decoders and more complex analysis engines.

*Based on work by Tom Karpiniec (http://thomask.sdf.org/blog/2017/09/01/layer-2-raw-sockets-on-rustlinux.html) and Herman Radtke (http://hermanradtke.com/2016/03/17/unions-rust-ffi.html)*
