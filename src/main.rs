use std::env;
use std::process::exit;
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::ptr;

mod util;
mod drcom;
mod auth;
mod eap;

static mut USERNAME: Option<String> = None;
static mut PASSWORD: Option<String> = None;
static mut ONLINE_HOOK_CMD: Option<String> = None;
static mut OFFLINE_HOOK_CMD: Option<String> = None;
static mut DEVICE_NAME: [u8; 16] = [0; 16];
static mut HOST_NAME: [u8; 32] = [0; 32];
static mut DNS_IPADDR: u32 = 0;
static mut UDP_SERVER_IPADDR: u32 = 0;
static mut VERSION: [u8; 16] = [0; 16];
static mut VERSION_LEN: usize = 0;
static mut HASH: Option<String> = None;
// static mut CLOGLEV: c_int = NONE;

// extern "C" fn handle_term(signal: c_int) {
//     unsafe {
//         LogWrite(ALL, INF, CString::new("Exiting...").unwrap().as_ptr());
//         auth_8021x_Logoff();
//         exit(0);
//     }
// }

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
    unsafe {

        let args: Vec<String> = env::args().collect();
        let mut client = 1;
        let mut a_hour: u8 = 255;
        let mut a_minute: u8 = 255;
        let mut retry_time = 1;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--username" | "-u" => {
                    i += 1;
                    USERNAME = Some(args[i].clone());
                }
                "--password" | "-p" => {
                    i += 1;
                    PASSWORD = Some(args[i].clone());
                }
                "--iface" | "-i" => {
                    i += 1;
                    DEVICE_NAME[..args[i].len()].copy_from_slice(args[i].as_bytes());
                }
                "--dns" | "-n" => {
                    i += 1;
                    DNS_IPADDR = args[i].parse().unwrap_or(0);
                }
                "--hostname" | "-H" => {
                    i += 1;
                    HOST_NAME[..args[i].len()].copy_from_slice(args[i].as_bytes());
                }
                "--udp-server" | "-s" => {
                    i += 1;
                    UDP_SERVER_IPADDR = args[i].parse().unwrap_or(0);
                }
                "--cli-version" | "-c" => {
                    i += 1;
                    // VERSION_LEN = hex::decode_to_slice(&args[i], &mut VERSION).unwrap_or(0);
                }
                "--net-time" | "-T" => {
                    i += 1;
                    let time_parts: Vec<&str> = args[i].split(':').collect();
                    if time_parts.len() == 2 {
                        a_hour = time_parts[0].parse().unwrap_or(255);
                        a_minute = time_parts[1].parse().unwrap_or(255);
                    }
                }
                "--hash" | "-h" => {
                    i += 1;
                    HASH = Some(args[i].clone());
                }
                "--online-hook" | "-E" => {
                    i += 1;
                    ONLINE_HOOK_CMD = Some(args[i].clone());
                }
                "--offline-hook" | "-Q" => {
                    i += 1;
                    OFFLINE_HOOK_CMD = Some(args[i].clone());
                }
                "--debug" | "-D" => {
                    // if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    //     i += 1;
                    //     CLOGLEV = args[i].parse().unwrap_or(DEBUG);
                    // } else {
                    //     CLOGLEV = DEBUG;
                    // }
                }
                "--logoff" | "-o" => {
                    // client = LOGOFF;
                }
                _ => {
                    print_help(&args[0]);
                    exit(-1);
                }
            }
            i += 1;
        }

        if HOST_NAME[0] == 0 {
            let hostname = CString::new("localhost").unwrap();
            // libc::gethostname(hostname.as_ptr() as *mut c_char, HOST_NAME.len());
            HOST_NAME[..hostname.to_bytes().len()].copy_from_slice(hostname.to_bytes());
        }

        // if client != LOGOFF && (USERNAME.is_none() || PASSWORD.is_none()) {
        //     LogWrite(INIT, ERROR, CString::new("Please specify username and password!").unwrap().as_ptr());
        //     exit(-1);
        // }

        if UDP_SERVER_IPADDR == 0 {
            UDP_SERVER_IPADDR = "127.0.0.1".parse().unwrap();
        }

        if DNS_IPADDR == 0 {
            DNS_IPADDR = "8.8.8.8".parse().unwrap();
        }

        // signal(SIGTERM, handle_term as usize);
        // signal(SIGINT, handle_term as usize);

        // loop {
        //     let ret = Authentication(client);
        //     if ret == 1 {
        //         retry_time = 1;
        //         LogWrite(ALL, INF, CString::new("Restart authentication.").unwrap().as_ptr());
        //     } else if ret == -libc::ENETUNREACH {
        //         LogWrite(ALL, INF, CString::new(format!("Retry in {} secs.", retry_time)).unwrap().as_ptr());
        //         std::thread::sleep(std::time::Duration::from_secs(retry_time));
        //         if retry_time <= 256 {
        //             retry_time *= 2;
        //         }
        //     } else {
        //         break;
        //     }
        // }

        // LogWrite(ALL, ERROR, CString::new("Exit.").unwrap().as_ptr());
    }
}
