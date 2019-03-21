extern crate tun_tap;
use std::io;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        if eth_proto != 0x0800 {
            // Ignore non IPV4
            continue;
        }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(p) => {
                let src = p.source_addr();
                let dst = p.destination_addr();
                let proto = p.protocol();
                if proto != 0x06 {
                    // Not TCP
                    continue;
                }
                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + p.slice().len()..]) {
                    Ok(t) => {
                        eprintln!(
                            "{} → {} {}b of tcp to port {}",
                            src,
                            dst,
                            t.slice().len(),
                            t.destination_port()
                        );
                    }
                    Err(e) => {
                        eprintln!("Ignoring TCP Packet {:?}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Ignoring packet {:?}", e);
            }
        }
    }
    Ok(())
}
