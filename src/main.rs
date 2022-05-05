use clap::Parser;
use ductile::connect_channel;
use magic_pake::common::Channel;
use magic_pake::fpake::HalfKey;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Address of where to connect.
    #[clap(short, long, default_value="localhost:8080")]
    address: String,

    #[clap(short, long)]
    server: bool,

    #[clap(short, long)]
    oblivous: bool,

    #[clap(short, long)]
    password: Vec<u8>,

    #[clap(short, long)]
    threadshold: u16,
}

fn main() {
    let args = Args::parse();
    let ch : Channel<Vec<u8>> = connect_channel(args.address).unwrap();
    if args.server {
        let hk1 = HalfKey::garbler(&args.password, args.threadshold, &ch).unwrap();
        let hk2 = HalfKey::evaluator(&args.password, &ch).unwrap();
        println!("Derived Key: {:?}", hk1.combine(hk2));
    } else {
        let hk2 = HalfKey::evaluator(&args.password, &ch).unwrap();
        let hk1 = HalfKey::garbler(&args.password, args.threadshold, &ch).unwrap();
        println!("Derived Key: {:?}", hk1.combine(hk2));
    }
}
