

mod util;
mod drcom;
mod auth;
mod eap;

fn print_help(argn: &str) {
    println!("Usage: {} --username <username> --password <password> [options...]
 -i, --iface <ifname> Interface to perform authentication.
 -n, --dns <dns> DNS server address to be sent to UDP server.
 -H, --hostname <hostname>
 -s, --udp-server <server>
 -c, --cli-version <client version>
 -T, --net-time <time> The time you are allowed to access internet. e.g. 6:10
 -h, --hash <hash> DrAuthSvr.dll hash value.
 -E, --online-hook <command> Command to be execute after EAP authentication success.
 -Q, --offline-hook <command> Command to be execute when you are forced offline at night.
 -D, --debug
 -o, --logoff", argn);
}

fn print_init() {
    log::info!("scutclient built at: {:?} {:?}", option_env!("DATE"), option_env!("TIME"));
    log::info!("Authored by Scutclient Project");
    log::info!("Source code available at https://github.com/scutclient/scutclient");
    log::info!("Contact us with QQ group 262939451");
    log::info!("#######################################");
}

fn main() {
}
