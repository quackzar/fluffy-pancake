use clap::Parser;
use magic_pake::common::mock::{connect_channel, ChannelServer};
use magic_pake::common::{Error, TChannel};
use magic_pake::fpake::HalfKey;
use magic_pake::legacy_fpake::OneOfManyKey;
use std::fs;

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

    /// Use oblivous fPAKE instead, requires password list.
    #[clap(short, long)]
    oblivous: bool,

    /// Password as bitstring, incompatible with `--oblvious` option.
    #[clap(short, long)]
    password: String,

    /// Threadshold used.
    #[clap(short, long, default_value_t = 0)]
    threadshold: u16,

    #[clap(short, long)]
    password_file: String,

    #[clap(long, default_value_t = 2048)]
    password_size: usize,

    // TODO: Make this option redundant.
    #[clap(long)]
    total_passwords: u32,

    #[clap(short, long)]
    index: u32,
}

fn server(args: &Args) -> Result<(), Error> {
    let pw = args.password.as_bytes();
    let mut server = ChannelServer::bind(&args.address)?;
    println!("Listening on {}...", &args.address);

    let (s, r) = server.next().unwrap();
    let ch = (s, r);

    let hk1 = HalfKey::garbler(&pw, args.threadshold, &ch)?;
    let hk2 = HalfKey::evaluator(&pw, &ch)?;
    println!("Derived Key: {:?}", hk1.combine(hk2));
    Ok(())
}

fn server_many(args: &Args) -> Result<(), Error> {
    let filename = &args.password_file;
    println!("Loading passwords...");
    let pws = fs::read(filename)?;
    let pws: Vec<Vec<u8>> = pws
        .chunks_exact(args.password_size)
        .map(|s| s.into())
        .collect();

    let mut server = ChannelServer::bind(&args.address)?;
    println!("Listening on {}...", &args.address);
    let (s, r) = server.next().unwrap();
    let ch = (s, r);

    // TODO: Redo to use new one of many fPAKE.
    let hk1 = OneOfManyKey::garbler_server(&pws, args.threadshold, &ch)?;
    let hk2 = OneOfManyKey::evaluator_server(&pws, &ch)?;
    println!("Derived Key: {:?}", hk1.combine(hk2));
    Ok(())
}

fn client(args: &Args) -> Result<(), Error> {
    let pw = args.password.as_bytes();
    println!("Connecting to {}...", &args.address);
    let ch: TChannel = connect_channel(&args.address)?;

    let hk2 = HalfKey::evaluator(&pw, &ch)?;
    let hk1 = HalfKey::garbler(&pw, args.threadshold, &ch)?;
    println!("Derived Key: {:?}", hk1.combine(hk2));
    Ok(())
}

fn client_many(args: &Args) -> Result<(), Error> {
    let pw = args.password.as_bytes();
    println!("Connecting to {}...", &args.address);
    let ch: TChannel = connect_channel(&args.address)?;

    // TODO: Redo to use new one of many fPAKE.
    let hk2 = OneOfManyKey::evaluator_client(&pw, args.total_passwords, args.index, &ch)?;
    let hk1 =
        OneOfManyKey::garbler_client(&pw, args.index, args.total_passwords, args.threadshold, &ch)?;
    println!("Derived Key: {:?}", hk1.combine(hk2));
    Ok(())
}

fn main() -> Result<(), Error> {
    let args = Args::parse();
    if args.server && args.oblivous {
        server_many(&args)?;
    } else if args.server {
        server(&args)?;
    } else if args.oblivous {
        client_many(&args)?;
    } else {
        client(&args)?;
    }
    Ok(())
}
