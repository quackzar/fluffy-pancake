// client binary for mfpake
use clap::Parser;
use magic_pake::common::raw::{connect_channel, ChannelServer};
use magic_pake::common::Result;
use magic_pake::common::{Error, TChannel};
use magic_pake::legacy_fpake::OneOfManyKey;
use magic_pake::many_fpake::mfpake_single;
use std::fs;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Address of where to connect.
    #[clap(short, long, default_value = "localhost:4321")]
    address: String,

    /// Password as bitstring, incompatible with `--oblvious` option.
    #[clap(short, long)]
    password: String,

    /// Threadshold used.
    #[clap(short, long, default_value_t = 0)]
    threshold: u16,

    // TODO: Make this option redundant.
    #[clap(long)]
    total_passwords: u32,

    #[clap(short, long)]
    index: u32,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let pw = args.password.as_bytes();
    println!("Connecting to {}...", &args.address);
    let ch: TChannel = connect_channel(&args.address)?;
    let key = mfpake_single(pw, args.index, args.total_passwords, args.threshold, &ch)?;
    println!("Derived Key: {:?}", key);
    Ok(())
}
