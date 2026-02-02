use std::net::Ipv4Addr;

use clap::Parser;

use scut_drcom_client::{Authenticator, Credentials};

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

    let credentials = Credentials::new(args.username, args.password, args.hostname, args.hash);

    let mut auth = Authenticator::new(&args.iface, credentials)?;

    log::info!("Local MAC: {}", auth.local_mac());
    log::info!("Local IP: {}", auth.local_ip());

    // Handle logoff-only mode
    if args.logoff {
        auth.logoff();
        log::info!("Logoff complete.");
        return Ok(());
    }

    auth.authenticate().map_err(|e| {
        log::error!("Authentication failed: {:?}", e);
        Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("{:?}", e),
        )) as Box<dyn std::error::Error>
    })?;

    Ok(())
}
