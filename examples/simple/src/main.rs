extern crate af_packet;
extern crate num_cpus;

use std::env;
use std::thread;

fn main() {
    let args: Vec<String> = env::args().collect();

    for x in 0..num_cpus::get() {
        let interface = args[1].clone();
        thread::spawn(move || {
            let tid = x;
            let mut packets: u64 = 0;
            let mut drops: u64 = 0;
            let ring = af_packet::Ring::from_if_name(&interface).unwrap();
            loop {
                let mut block = ring.get_block(); //THIS WILL BLOCK
                for _packet in block.get_raw_packets() {
                    //do something
                    //println!("{:?}", packet);
                }

                //these stats are updated per-block and are not cumulative
                let stats = ring.get_rx_statistics().unwrap();

                packets += stats.tp_packets as u64;
                drops += stats.tp_drops as u64;

                println!("Thread {} has received {} packets and dropped {}", tid, packets, drops);

                block.mark_as_consumed();
            }
        });
    }
    loop {
        thread::sleep_ms(1000);
    }
}
