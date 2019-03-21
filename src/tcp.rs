use std::io;

enum State {
    Closed,
    Listen,
    // SynRcvd,
    // Established,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
}

struct SendSequenceSpace {
    // send unacknowledged
    una: usize,
    // send next
    nxt: usize,
    // send window
    wnd: usize,
    // send urgent pointer
    up: bool,
    // segment sequence number
    wl1: usize,
    // segment acknowlegement number
    wl2: usize,
    // initial sequence number
    iss: usize,
}

struct ReceiveSequenceSpace {
    // receive next
    nxt: usize,
    // receive window
    wnd: usize,
    // receive urgent pointer
    up: bool,
    // initial receive sequence number
    irs: usize,
}

impl Default for Connection {
    fn default() -> Self {
        //State::Closed
        Connection {
            state: State::Listen,
        }
    }
}

impl State {
    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        match *self {
            State::Closed => {
                return Ok(0);
            }
            State::Listen => {
                if !tcph.syn() {
                    // Expect syn packet, return if not
                    return Ok(0);
                }

                // Start establishing connection
                let mut syn_ack = etherparse::TcpHeader::new(
                    tcph.destination_port(),
                    tcph.source_port(),
                    unimplemented!(),
                    unimplemented!(),
                );
                syn_ack.syn = true;
                syn_ack.ack = true;
                let mut ip = etherparse::Ipv4Header::new(
                    syn_ack.header_len(),
                    64,
                    etherparse::IpTrafficClass::Tcp,
                    [
                        iph.destination()[0],
                        iph.destination()[1],
                        iph.destination()[2],
                        iph.destination()[3],
                    ],
                    [
                        iph.source()[0],
                        iph.source()[1],
                        iph.source()[2],
                        iph.source()[3],
                    ],
                );
                // Write out the headers
                let unwritten = {
                    let mut unwritten = &mut buf[..];
                    ip.write(&mut unwritten);
                    syn_ack.write(&mut unwritten);
                    unwritten.len()
                };
                nic.send(&buf[..unwritten]);
            }
        }
    }
}
