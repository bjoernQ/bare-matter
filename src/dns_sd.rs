use core::str::FromStr;

use crate::{
    dns_sd_codec::{
        self, DnsMessage, DnsValue, MessageType, Record, RecordClass, RecordType, SrvRecordValue,
    },
    fabric::Fabric,
    MatterContext, UdpMulticastSocket,
};

pub struct DnsSd<'a> {
    socket: &'a mut dyn UdpMulticastSocket,
    local_ip: [u8; 4],
    next_announce: u64,
    context: &'a MatterContext,
}

impl<'a> DnsSd<'a> {
    pub fn new(
        local_ip: [u8; 4],
        socket: &'a mut dyn UdpMulticastSocket,
        context: &'a MatterContext,
    ) -> DnsSd<'a> {
        socket.bind(&[224, 0, 0, 251], 5353).unwrap();

        DnsSd {
            socket,
            local_ip,
            next_announce: 0,
            context,
        }
    }

    pub fn handle_incoming(&mut self) {
        let msg = self.socket.receive();

        if let Ok((msg, _from, _port)) = msg {
            let dns_msg = dns_sd_codec::decode(msg.as_slice());
            log::trace!("{:?}", dns_msg);
        }
    }

    pub fn handle_announce(&mut self, timestamp: u64) {
        if timestamp > self.next_announce {
            self.next_announce += 10_000; // announce every 10 secs for now

            let msg = self.create_announcement_message();
            log::trace!("send announcement");
            log::trace!("{:?}", msg);
            let res = dns_sd_codec::encode(msg);

            if let Ok(res) = res {
                self.socket.send([224, 0, 0, 251], 5353, res).unwrap();
            }
        }
    }

    // TODO fabric stuff
    fn create_announcement_message(&self) -> DnsMessage {
        self.context.with_fabric(|fabric| {
            if !fabric.configured {
                self.create_announcement_message_no_fabric()
            } else {
                self.create_announcement_messsage_with_fabric(fabric)
            }
        })
    }

    fn create_announcement_messsage_with_fabric(&self, fabric: &Fabric) -> DnsMessage {
        use core::fmt::Write;

        let hostname = "401C8310A42D0000.local";
        let op_id = fabric.operational_id.clone();
        let mut operational_id: heapless::String<32> = heapless::String::new();
        for b in op_id {
            write!(operational_id, "{:02X}", b).unwrap();
        }

        const SERVICE_DISCOVERY_QNAME: &str = "_services._dns-sd._udp.local";
        const MATTER_SERVICE_QNAME: &str = "_matter._tcp.local";

        let mut fabric_q_name: heapless::String<55> = heapless::String::new();
        write!(
            fabric_q_name,
            "_I{}._sub.{}",
            operational_id, MATTER_SERVICE_QNAME
        )
        .unwrap();

        let mut device_matter_q_name: heapless::String<55> = heapless::String::new();
        write!(
            device_matter_q_name,
            "{}-{:016X}.{}",
            operational_id, fabric.node_id, MATTER_SERVICE_QNAME
        )
        .unwrap();

        DnsMessage {
            transaction_id: 0,
            message_type: MessageType::Response,
            queries: heapless::Vec::new(),
            answers: heapless::Vec::from_slice(&[
                ptr_record(SERVICE_DISCOVERY_QNAME, MATTER_SERVICE_QNAME),
                ptr_record(SERVICE_DISCOVERY_QNAME, &fabric_q_name),
                ptr_record(MATTER_SERVICE_QNAME, &device_matter_q_name),
                ptr_record(&fabric_q_name, &device_matter_q_name),
            ])
            .unwrap(),
            authorities: heapless::Vec::new(),
            additional_records: heapless::Vec::from_slice(&[
                Record {
                    name: heapless::String::from_str(hostname).unwrap(),
                    record_type: RecordType::A,
                    record_class: RecordClass::IN,
                    ttl: 120,
                    value: DnsValue::A(
                        self.local_ip[0],
                        self.local_ip[1],
                        self.local_ip[2],
                        self.local_ip[3],
                    ),
                },
                Record {
                    name: heapless::String::from_str(&device_matter_q_name).unwrap(),
                    record_type: RecordType::SRV,
                    record_class: RecordClass::IN,
                    ttl: 120,
                    value: DnsValue::Srv(SrvRecordValue {
                        priority: 0,
                        weight: 0,
                        port: 5540,
                        target: heapless::String::from_str(hostname).unwrap(),
                    }),
                },
                Record {
                    name: heapless::String::from_str(&device_matter_q_name).unwrap(),
                    record_type: RecordType::TXT,
                    record_class: RecordClass::IN,
                    ttl: 120,
                    value: DnsValue::Txt(
                        heapless::Vec::from_slice(&[
                            heapless::String::from_str("SII=5000").unwrap(), // sleep idle interval
                            heapless::String::from_str("SAI=300").unwrap(), // sleep activity interval
                            heapless::String::from_str("T=1").unwrap(),     // tcp supported
                        ])
                        .unwrap(),
                    ),
                },
            ])
            .unwrap(),
        }
    }

    fn create_announcement_message_no_fabric(&self) -> DnsMessage {
        let discriminator = 3840u32;
        let _short_discriminator = (discriminator >> 8) & 0x0f;

        let _instance_id = "58158C3432DE32FA";
        let vendor_q_name = "_V65521._sub._matterc._udp.local"; // vendor id
        let device_type_q_name = "_T257._sub._matterc._udp.local"; // device type
        let short_discriminator_q_name = "_S15._sub._matterc._udp.local"; // short discr
        let long_discriminator_q_name = "_L3840._sub._matterc._udp.local";
        let commission_q_name = "_CM._sub._matterc._udp.local";
        let device_q_name = "58158C3432DE32FA._matterc._udp.local";

        let hostname = "401C8310A42D0000.local";

        const SERVICE_DISCOVERY_QNAME: &str = "_services._dns-sd._udp.local";

        DnsMessage {
            transaction_id: 0,
            message_type: MessageType::Response,
            queries: heapless::Vec::new(),
            answers: heapless::Vec::from_slice(&[
                ptr_record(SERVICE_DISCOVERY_QNAME, "_matterc._udp.local"),
                ptr_record(SERVICE_DISCOVERY_QNAME, vendor_q_name),
                ptr_record(SERVICE_DISCOVERY_QNAME, device_type_q_name),
                ptr_record(SERVICE_DISCOVERY_QNAME, short_discriminator_q_name),
                ptr_record(SERVICE_DISCOVERY_QNAME, long_discriminator_q_name),
                ptr_record(SERVICE_DISCOVERY_QNAME, commission_q_name),
                ptr_record("_matterc._udp.local", device_q_name),
                ptr_record(vendor_q_name, device_q_name),
                ptr_record(device_type_q_name, device_q_name),
                ptr_record(short_discriminator_q_name, device_q_name),
                ptr_record(long_discriminator_q_name, device_q_name),
                ptr_record(commission_q_name, device_q_name),
            ])
            .unwrap(),
            authorities: heapless::Vec::new(),
            additional_records: heapless::Vec::from_slice(&[
                Record {
                    name: heapless::String::from_str(device_q_name).unwrap(),
                    record_type: RecordType::SRV,
                    record_class: RecordClass::IN,
                    ttl: 120,
                    value: DnsValue::Srv(SrvRecordValue {
                        priority: 0,
                        weight: 0,
                        port: 5540,
                        target: heapless::String::from_str(hostname).unwrap(),
                    }),
                },
                Record {
                    name: heapless::String::from_str(hostname).unwrap(),
                    record_type: RecordType::A,
                    record_class: RecordClass::IN,
                    ttl: 120,
                    value: DnsValue::A(
                        self.local_ip[0],
                        self.local_ip[1],
                        self.local_ip[2],
                        self.local_ip[3],
                    ),
                },
                Record {
                    name: heapless::String::from_str(device_q_name).unwrap(),
                    record_type: RecordType::TXT,
                    record_class: RecordClass::IN,
                    ttl: 120,
                    value: DnsValue::Txt(
                        heapless::Vec::from_slice(&[
                            heapless::String::from_str("VP=65521+32769").unwrap(), // vendor id + product
                            heapless::String::from_str("DT=257").unwrap(),         // device type
                            heapless::String::from_str("DN=Matter test device").unwrap(), // device name
                            heapless::String::from_str("SII=5000").unwrap(), // sleep idle interval
                            heapless::String::from_str("SAI=300").unwrap(), // sleep activity interval
                            heapless::String::from_str("T=1").unwrap(),     // tcp supported
                            heapless::String::from_str("D=3840").unwrap(),  // discriminator
                            heapless::String::from_str("CM=1").unwrap(),    // comission mode
                            heapless::String::from_str("PH=33").unwrap(),   // pairing hint
                            heapless::String::from_str("PI=").unwrap(),     // pairing instruction
                        ])
                        .unwrap(),
                    ),
                },
            ])
            .unwrap(),
        }
    }
}

fn ptr_record(name: &str, ptr: &str) -> Record {
    Record {
        name: heapless::String::from_str(name).unwrap(),
        record_type: RecordType::PTR,
        record_class: RecordClass::IN,
        ttl: 120,
        value: DnsValue::Ptr(heapless::String::from_str(ptr).unwrap()),
    }
}
