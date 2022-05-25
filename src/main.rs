// main.rs for vanilla fPAKE.
use clap::Parser;
use magic_pake::common::Result;
use magic_pake::common::auth::{connect_channel, ChannelServer};
use magic_pake::fpake::HalfKey;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Address of where to connect.
    #[clap(short, long, default_value = "localhost:8080")]
    address: String,

    /// Run in server mode (garbler first).
    #[clap(short, long)]
    server: bool,

    /// Password as bitstring, incompatible with `--oblvious` option.
    #[clap(short, long)]
    password: String,

    /// Threadshold used.
    #[clap(short, long, default_value_t = 0)]
    threadshold: u16,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let pw = args.password.as_bytes();
    let key = if args.server {
        let mut server = ChannelServer::bind(&args.address)?;
        println!("Listening on {}...", &args.address);
        let (s, r) = server.next().unwrap();
        let ch = (s, r);

        let hk1 = HalfKey::garbler(pw, args.threadshold, &ch)?;
        let hk2 = HalfKey::evaluator(pw, &ch)?;
        hk1.combine(hk2)
    } else {
        println!("Connecting to {}...", &args.address);
        let ch = connect_channel(&args.address)?;

        let hk2 = HalfKey::evaluator(pw, &ch)?;
        let hk1 = HalfKey::garbler(pw, args.threadshold, &ch)?;
        hk1.combine(hk2)
    };
    println!("Derived Key: {:?}", key);
    Ok(())
}


