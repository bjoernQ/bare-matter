use bare_matter::{
    create_on_off_endpoint, create_root_device, interaction_model::*, Certificates, MatterContext,
    MatterServer, UdpMulticastSocket,
};
use socket2::SockAddr;
use std::{
    convert::TryInto,
    mem::MaybeUninit,
    net::{SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};

// for the example set LOCAL_IP env variable like 192.168.2.125
const LOCAL_IP: &str = env!("LOCAL_IP");

// From Chip-Test-DAC-FFF1-8000-0007-Key.der
const DEVICE_PRIVATE_KEY: [u8; 32] =
    hex_literal::hex!("727F1005CBA47ED7822A9D930943621617CFD3B79D9AF528B801ECF9F1992204");

// From Chip-Test-DAC-FFF1-8000-0007-Cert.der
const DEVICE_CERTIFICATE: [u8;492] = hex_literal::hex!("308201e83082018fa0030201020208143c9d1689f498f0300a06082a8648ce3d04030230463118301606035504030c0f4d617474657220546573742050414931143012060a2b0601040182a27c02010c044646463131143012060a2b0601040182a27c02020c04383030303020170d3231303632383134323334335a180f39393939313233313233353935395a304b311d301b06035504030c144d6174746572205465737420444143203030303731143012060a2b0601040182a27c02010c044646463131143012060a2b0601040182a27c02020c04383030303059301306072a8648ce3d020106082a8648ce3d0301070342000462e2b6e1baff8d74a6fd8216c4cb67a3363a31e691492792e61aee610261481396725ef95e142686ba98f339b0ff65bc338bec7b9e8be0bdf3b2774982476220a360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d0e04160414ee95ad96983a9ea95bcd2b00dc5e671727690383301f0603551d23041830168014af42b7094debd515ec6ecf33b81115225f325288300a06082a8648ce3d040302034700304402202f51cf53bf7777df7318094b9db595eebf2fa881c8c572847b1e689ece654264022029782708ee6b32c7f08ff63dbe618e9a580bb14c183bc288777adf9e2dcff5e6");

// From Chip-Test-PAI-FFF1-8000-Cert.der
const PRODUCT_INTERMEDIATE_CERTIFICATE: [u8;472] = hex_literal::hex!("308201d43082017aa00302010202083e6ce6509ad840cd300a06082a8648ce3d04030230303118301606035504030c0f4d617474657220546573742050414131143012060a2b0601040182a27c02010c04464646313020170d3231303632383134323334335a180f39393939313233313233353935395a30463118301606035504030c0f4d617474657220546573742050414931143012060a2b0601040182a27c02010c044646463131143012060a2b0601040182a27c02020c04383030303059301306072a8648ce3d020106082a8648ce3d0301070342000480ddf11b228f3e31f63bcf5798da14623aebbde82ef378eeadbfb18fe1abce31d08ed4b20604b6ccc6d9b5fab64e7de10cb74be017c9ec1516056d70f2cd0b22a366306430120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020106301d0603551d0e04160414af42b7094debd515ec6ecf33b81115225f325288301f0603551d230418301680146afd22771f511fecbf1641976710dcdc31a1717e300a06082a8648ce3d040302034800304502210096c9c8cf2e01886005d8f5bc72c07b75fd9a57695ac4911131138bea033ce50302202554943be57d53d6c475f7d23ebfcfc2036cd29ba6393ec7efad8714ab718219");

// From DeviceAttestationCredsExample.cpp
const CERTIFICATE_DECLARATION: [u8;541] = hex_literal::hex!("3082021906092a864886f70d010702a082020a30820206020103310d300b06096086480165030402013082017106092a864886f70d010701a08201620482015e152400012501f1ff3602050080050180050280050380050480050580050680050780050880050980050a80050b80050c80050d80050e80050f80051080051180051280051380051480051580051680051780051880051980051a80051b80051c80051d80051e80051f80052080052180052280052380052480052580052680052780052880052980052a80052b80052c80052d80052e80052f80053080053180053280053380053480053580053680053780053880053980053a80053b80053c80053d80053e80053f80054080054180054280054380054480054580054680054780054880054980054a80054b80054c80054d80054e80054f80055080055180055280055380055480055580055680055780055880055980055a80055b80055c80055d80055e80055f80056080056180056280056380182403162c04135a494732303134325a423333303030332d32342405002406002507942624080018317d307b020103801462fa823359acfaa9963e1cfa140addf504f37160300b0609608648016503040201300a06082a8648ce3d04030204473045022024e5d1f47a7d7b0d206a26ef699b7c9757b72d469089de3192e678c745e7f60c022100f8aa2fa711fcb79b97e397ceda667bae464e2bd3ffdfc3cced7aa8ca5f4c1a7c");

pub fn main() {
    env_logger::init();

    let mut local_ip = [0u8; 4];
    for (i, octet) in LOCAL_IP.split(".").into_iter().enumerate() {
        local_ip[i] = octet.parse().unwrap();
    }

    let certificates = Certificates {
        device_private_key: DEVICE_PRIVATE_KEY,
        device_certificate: heapless::Vec::from_slice(&DEVICE_CERTIFICATE).unwrap(),
        product_intermediate_certificate: heapless::Vec::from_slice(
            &PRODUCT_INTERMEDIATE_CERTIFICATE,
        )
        .unwrap(),
        certificate_declaration: heapless::Vec::from_slice(&CERTIFICATE_DECLARATION).unwrap(),
    };

    let context = MatterContext::new(certificates);

    let on_handler = |v, _s: &MatterContext| {
        println!("\n\non_handler {:?}\n\n", v);
        InvokeHandlerResponse::Result(0)
    };
    let off_handler = |v, _s: &MatterContext| {
        println!("\n\noff_handler {:?}\n\n", v);
        InvokeHandlerResponse::Result(0)
    };
    let toggle_handler = |v, _ctx: &MatterContext| {
        println!("\n\ntoggle_handler {:?}\n\n", v);
        InvokeHandlerResponse::Result(0)
    };

    let endpoints = &[
        create_root_device!(),
        create_on_off_endpoint!(on_handler, off_handler, toggle_handler),
    ];

    let mut device = Device::new(endpoints);

    let mut rng = crypto_bigint::rand_core::OsRng;
    let mut socket = StdUdpSocket::new();
    let mut multicast_socket = StdUdpMulticastSocket::new(local_ip);
    let mut server = MatterServer::new(
        &mut socket,
        &mut multicast_socket,
        local_ip,
        &mut rng,
        &mut device,
        &context,
    );

    let instant = Instant::now();
    loop {
        let millis = instant.elapsed().as_millis() as u64;
        server.poll(millis);
    }
}

pub struct StdUdpSocket {
    udp_socket: Option<UdpSocket>,
}

impl StdUdpSocket {
    pub fn new() -> StdUdpSocket {
        StdUdpSocket { udp_socket: None }
    }
}

impl bare_matter::UdpSocket for StdUdpSocket {
    fn send(
        &mut self,
        addr: [u8; 4],
        port: u16,
        buffer: heapless::Vec<u8, 1024>,
    ) -> Result<(), ()> {
        if let Some(ref socket) = &self.udp_socket {
            socket
                .send_to(
                    buffer.as_slice(),
                    format!("{}.{}.{}.{}:{}", addr[0], addr[1], addr[2], addr[3], port),
                )
                .unwrap();
        }
        Ok(())
    }

    fn receive(&mut self) -> Result<(heapless::Vec<u8, 1024>, [u8; 4], u16), ()> {
        if let Some(ref socket) = &self.udp_socket {
            let mut buf = [0u8; 2048];
            let res = socket.recv_from(&mut buf);

            if let Ok((len, from)) = res {
                let mut result = heapless::Vec::new();
                result.extend_from_slice(&buf[..len]).unwrap();

                let addr = match from.ip() {
                    std::net::IpAddr::V4(ip) => ip.octets().try_into().unwrap(),
                    std::net::IpAddr::V6(_) => todo!(),
                };
                let port = from.port();

                return Ok((result, addr, port));
            }
        }
        Err(())
    }

    fn bind(&mut self, port: u16) -> Result<(), ()> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", port)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        self.udp_socket = Some(socket);
        Ok(())
    }
}

pub struct StdUdpMulticastSocket {
    local_ip: [u8; 4],
    socket: Option<socket2::Socket>,
}

impl StdUdpMulticastSocket {
    pub fn new(local_ip: [u8; 4]) -> StdUdpMulticastSocket {
        StdUdpMulticastSocket {
            local_ip,
            socket: None,
        }
    }
}

impl UdpMulticastSocket for StdUdpMulticastSocket {
    fn send(
        &mut self,
        addr: [u8; 4],
        port: u16,
        buffer: heapless::Vec<u8, 2048>,
    ) -> Result<(), ()> {
        let addr: SocketAddrV4 =
            format!("{}.{}.{}.{}:{}", addr[0], addr[1], addr[2], addr[3], port)
                .parse()
                .unwrap();
        let addr = SockAddr::from(addr);
        self.socket
            .as_mut()
            .unwrap()
            .send_to(buffer.as_slice(), &addr)
            .unwrap();
        Ok(())
    }

    fn receive(&mut self) -> Result<(heapless::Vec<u8, 2048>, [u8; 4], u16), ()> {
        if let Some(ref socket) = &self.socket {
            let mut buf = [MaybeUninit::new(0u8); 2048];
            let res = socket.recv_from(&mut buf);

            if let Ok((len, from)) = res {
                let mut result = heapless::Vec::new();
                for b in &buf[..len] {
                    result.push(unsafe { b.assume_init() }).unwrap();
                }

                let addr = from
                    .as_socket_ipv4()
                    .unwrap()
                    .ip()
                    .octets()
                    .try_into()
                    .unwrap();
                let port = from.as_socket_ipv4().unwrap().port();

                return Ok((result, addr, port));
            }
        }
        Err(())
    }

    fn bind(&mut self, multiaddr: &[u8; 4], port: u16) -> Result<(), ()> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        let address: std::net::SocketAddr = format!(
            "{}.{}.{}.{}:{}",
            self.local_ip[0], self.local_ip[1], self.local_ip[2], self.local_ip[3], port
        )
        .parse()
        .unwrap();
        socket.set_reuse_address(true).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(1)))
            .unwrap();
        socket.bind(&address.into()).unwrap();
        socket
            .join_multicast_v4(
                &format!(
                    "{}.{}.{}.{}",
                    multiaddr[0], multiaddr[1], multiaddr[2], multiaddr[3]
                )
                .parse()
                .unwrap(),
                &"0.0.0.0".parse().unwrap(),
            )
            .unwrap();

        self.socket = Some(socket);

        Ok(())
    }
}
