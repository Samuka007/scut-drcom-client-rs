use std::net::Ipv4Addr;

use clap::Parser;

mod auth;
mod drcom;
mod eap;
mod net;
mod util;

use auth::{Dot1xAuth, UdpAuthBuilder};

use crate::auth::Auth;

#[derive(Parser)]
#[command(name = "scut-drcom-client")]
#[command(about = "SCUT DrCom authentication client")]
struct Args {
    #[arg(short, long)]
    username: String,

    #[arg(short, long)]
    password: String,

    #[arg(short, long)]
    iface: String,

    #[arg(short = 'n', long, default_value = "222.201.130.30")]
    dns: Ipv4Addr,

    #[arg(short = 'H', long, default_value = "DRCOM")]
    hostname: String,

    #[arg(short = 'h', long, default_value = "")]
    hash: String,

    #[arg(short = 'D', long)]
    debug: bool,

    /// Send logoff packets and exit (without full authentication)
    #[arg(short = 'o', long)]
    logoff: bool,
}

fn print_init() {
    log::info!(
        "scutclient built at: {:?} {:?}",
        option_env!("DATE"),
        option_env!("TIME")
    );
    log::info!("Authored by Scutclient Project");
    log::info!("Source code available at https://github.com/scutclient/scutclient");
    log::info!("Contact us with QQ group 262939451");
    log::info!("#######################################");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.debug {
        std::env::set_var("RUST_LOG", "debug");
    } else {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    print_init();

    log::info!("Using interface: {}", args.iface);

    let mut dot1x = Dot1xAuth::new(&args.iface, args.username.clone(), args.password.clone())?;

    log::info!("Local MAC: {}", dot1x.local_mac());
    log::info!("Local IP: {}", dot1x.local_ip());

    // Handle logoff-only mode
    if args.logoff {
        dot1x.logoff();
        log::info!("Logoff complete.");
        return Ok(());
    }

    let udp = UdpAuthBuilder::default()
        .addr(dot1x.local_ip())
        .mac(dot1x.local_mac())
        .username(args.username)
        // .password(args.password)
        .hostname(args.hostname)
        .hash(args.hash)
        .build()?;

    let mut auth = Auth::new(dot1x, udp);

    auth.authentication().map_err(|e| {
        log::error!("Authentication failed: {:?}", e);
        Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("{:?}", e),
        )) as Box<dyn std::error::Error>
    })?;

    Ok(())
}
