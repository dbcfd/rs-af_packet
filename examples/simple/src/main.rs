extern crate af_packet;
extern crate num_cpus;

use std::env;
use std::thread;

fn main() {
    let args: Vec<String> = env::args().collect();

    for _ in 0..num_cpus::get() {
        let interface = args[1].clone();
        thread::spawn(move||{
            let ring = af_packet::Ring::from_if_name(&interface).unwrap();
            loop {
                let mut block = ring.get_block(); //THIS WILL BLOCK
                for packet in block.get_raw_packets() {
                    println!("{:?}", packet);
                }
                block.mark_as_consumed();
            }
        });
    }
}
