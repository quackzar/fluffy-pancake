use clap::Parser;
use ductile::{connect_channel, ChannelServer};
use magic_pake::common::Channel;
use magic_pake::fpake::HalfKey;
use magic_pake::common::Error;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Address of where to connect.
    #[clap(short, long, default_value="localhost:8080")]
    address: String,

    /// Run in server mode (garbler first).
    #[clap(short, long)]
    server: bool,

    /// Use oblivous fPAKE instead, requires password list.
    #[clap(short, long)]
    oblivous: bool,

    /// Password as bitstring, incompatible with `--oblvious` option.
    #[clap(short, long)]
    password: String,

    /// Threadshold used.
    #[clap(short, long, default_value="0")]
    threadshold: u16,
}



fn server_main(args : &Args) -> Result<(),Error> {
    let pw = args.password.as_bytes();
    let mut server = ChannelServer::bind(&args.address)?;
    println!("Listening on {}...", &args.address);

    let (s, r, _addr) = server.next().unwrap();
    let ch = (s,r);

    let hk1 = HalfKey::garbler(&pw, args.threadshold, &ch).unwrap();
    let hk2 = HalfKey::evaluator(&pw, &ch).unwrap();
    println!("Derived Key: {:?}", hk1.combine(hk2));
    Ok(())
}

fn client_main(args : &Args) -> Result<(),Error> {
    let pw = args.password.as_bytes();
    println!("Connecting to {}...", &args.address);
    let ch : Channel<Vec<u8>> = connect_channel(&args.address)?;

    let hk2 = HalfKey::evaluator(&pw, &ch).unwrap();
    let hk1 = HalfKey::garbler(&pw, args.threadshold, &ch).unwrap();
    println!("Derived Key: {:?}", hk1.combine(hk2));
    Ok(())
}

fn main() -> Result<(),Error>  {
    let args = Args::parse();
    if args.server {
        server_main(&args)?;
    } else {
        client_main(&args)?;
    }
    Ok(())
}
