use clap::Parser;

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

    // create ARP packet

    // send ARP packet

    // recieve ARP packet
}

#[derive(Debug, Parser)]
/// A tool for scanning devices in a local network by sending ARP requests.
struct Cli {
    #[arg(short, long, required = true)]
    /// The network interface to use.
    interface: String,
}
