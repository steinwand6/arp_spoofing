use std::net::Ipv4Addr;

use clap::Parser;
use pnet::{
    datalink::{self, NetworkInterface},
    packet::{
        arp::{ArpHardwareType, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
        Packet,
    },
    util::MacAddr,
};

// Constants used to help locate our nested packets
const PKT_ETH_SIZE: usize = EthernetPacket::minimum_packet_size();
const PKT_ARP_SIZE: usize = ArpPacket::minimum_packet_size();

fn main() {
    let cli = Cli::parse();

    // get interface
    let interface_name = cli.interface;
    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Interface not found");
    println!("{:?}", interface);

    // get target info
    let local_info = IpMacPair::new(&interface);

    let target_ip: Ipv4Addr = cli
        .target_ip
        .parse()
        .expect("Unable to parse target_ip as IPv4 address");
    let target_info = get_addr_by_ip(&interface, &local_info, target_ip);
    println!("{:?}", target_info);

    // get source info
    let source_ip: Ipv4Addr = cli
        .source_ip
        .parse()
        .expect("Unable to parse source_ip as IPv4 address");
    let source_info = get_addr_by_ip(&interface, &local_info, source_ip);
    println!("{:?}", source_info);

    // send ARP packet

    // recieve ARP packet
}

#[derive(Debug)]
struct IpMacPair {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
}

impl IpMacPair {
    pub fn new(iface: &NetworkInterface) -> Self {
        let mac = iface.mac.expect("Unable to get MAC address");
        let ip = iface
            .ips
            .iter()
            .find(|&ip| ip.is_ipv4())
            .expect("Unable to get IP address")
            .ip()
            .to_string()
            .parse()
            .unwrap();
        Self { ip, mac }
    }
}

#[derive(Debug, Parser)]
/// A tool for performing ARP spoofing in a local network.
/// This tool sends falsified ARP responses to redirect traffic intended for a specific IP address.
struct Cli {
    /// The network interface to use for sending ARP packets.
    #[arg(short, long, required = true)]
    interface: String,

    /// The IP address of the target machine to spoof.
    #[arg(short, long, required = true)]
    target_ip: String,

    /// The IP address you want to impersonate (the source IP in the ARP response).
    #[arg(short, long, required = true)]
    source_ip: String,
}

fn create_arp_request<'a>(
    arp_packet: &'a mut [u8],
    sender_info: &IpMacPair,
    target_info: &IpMacPair,
) -> MutableArpPacket<'a> {
    let mut packet = MutableArpPacket::new(arp_packet).expect("Failed to create ARP Req");
    packet.set_hardware_type(ArpHardwareType::new(1));
    packet.set_protocol_type(EtherTypes::Ipv4);
    packet.set_hw_addr_len(6);
    packet.set_proto_addr_len(4);
    packet.set_operation(ArpOperations::Request);
    packet.set_sender_hw_addr(sender_info.mac);
    packet.set_sender_proto_addr(sender_info.ip);
    packet.set_target_hw_addr(MacAddr::zero());
    packet.set_target_proto_addr(target_info.ip);
    packet
}

fn get_addr_by_ip(
    interface: &NetworkInterface,
    local_info: &IpMacPair,
    target_ip: Ipv4Addr,
) -> Option<IpMacPair> {
    let mut target_info = IpMacPair {
        ip: target_ip,
        mac: MacAddr::zero(),
    };

    let mut arp_req_ = [0; PKT_ARP_SIZE];
    let arp_req = create_arp_request(&mut arp_req_, &local_info, &target_info);
    let mut ether_req_ = [0; PKT_ETH_SIZE + PKT_ARP_SIZE];
    let mut ether_req =
        MutableEthernetPacket::new(&mut ether_req_).expect("Failed to create ethernet packet");
    ether_req.set_destination(MacAddr::broadcast());
    ether_req.set_source(local_info.mac);
    ether_req.set_ethertype(EtherTypes::Arp);
    ether_req.set_payload(arp_req.packet());

    let (mut ds, mut dr) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(ds, dr)) => (ds, dr),
        Ok(_) => panic!("not channel"),
        Err(e) => {
            panic!("error {}", e);
        }
    };
    ds.send_to(ether_req.packet(), None);
    match dr.next() {
        Ok(p) => {
            let ehter_repaly = EthernetPacket::new(p).expect("Failed to get Ether packet");
            let arp_reply =
                ArpPacket::new(ehter_repaly.payload()).expect("Failed to get ARP packet");
            if arp_reply.get_operation() == ArpOperations::Reply {
                target_info.ip = arp_reply.get_sender_proto_addr();
                target_info.mac = arp_reply.get_sender_hw_addr();
            } else {
                eprintln!("Failed to get target address info");
                return None;
            }
        }
        Err(e) => print!("{e}"),
    }
    Some(target_info)
}
