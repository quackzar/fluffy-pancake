// server main for mfpake
use clap::Parser;
use magic_pake::common::auth::ChannelServer;
use magic_pake::common::Result;
use magic_pake::many_fpake::mfpake_many;
use std::fs;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Address of where to connect.
    #[clap(short, long, default_value = "localhost:4321")]
    address: String,

    // Threadshold used.
    #[clap(short, long, default_value_t = 0)]
    threadshold: u16,

    // Path for the binary file containing passwords
    #[clap(short, long, default_value = "./passwords")]
    password_file: String,

    // Size of the passwords in bits.
    #[clap(long, default_value_t = 2048)]
    password_size: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();
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
    let key = mfpake_many(&pws, args.threadshold, &ch)?;
    println!("Derived Key: {:?}", key);
    Ok(())
}
