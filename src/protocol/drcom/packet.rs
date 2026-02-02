use std::net::Ipv4Addr;

pub fn crc32(data: &[u8]) -> u32 {
    let mut ret: u32 = 0;
    let data_len = data.len();
    let mut i = 0;

    while i < data_len {
        let chunk = if i + 4 <= data_len {
            u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
        } else {
            let mut temp = [0u8; 4];
            temp[..(data_len - i)].copy_from_slice(&data[i..data_len]);
            u32::from_le_bytes(temp)
        };
        ret ^= chunk;
        ret &= 0xFFFFFFFF;
        i += 4;
    }

    ret = ret.to_le();
    ret = ret.wrapping_mul(19680126);
    ret = ret.to_le();

    ret
}

pub fn encrypt_info(info: &mut [u8; 16]) {
    let mut chartmp = [0u8; 16];
    for i in 0..16 {
        chartmp[i] = (info[i] << (i & 0x07)) + (info[i] >> (8 - (i & 0x07)));
    }
    info.copy_from_slice(&chartmp);
}

/// UDP MISC_START_ALIVE
pub fn misc_start_alive_setter(send_data: &mut [u8]) -> usize {
    let data = [0x07, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00];
    send_data[..data.len()].copy_from_slice(&data);
    data.len()
}

pub fn misc_start_alive_setter_immediate() -> [u8; 8] {
    [0x07, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00]
}

/// UDP MISC_RESPONSE_FOR_ALIVE
#[allow(clippy::too_many_arguments)]
pub fn misc_info_setter(
    send_data: &mut [u8],
    recv_data: &[u8],
    crc_md5_info: &mut [u8; 16],
    username: &str,
    hostname: &str,
    mac: &[u8],
    local_ipaddr: Ipv4Addr,
    dns_ipaddr: Ipv4Addr,
    version: &[u8],
    hash: &[u8],
) -> usize {
    let mut packetlen = 0;

    let header = [
        0x07, // Code
        0x01, // id
        0xf4, // len(packet length low byte, must be even length)
        0x00, // len(244 high byte)
        0x03, // step
    ];
    send_data[..header.len()].copy_from_slice(&header);
    packetlen += header.len();

    // uid len
    send_data[packetlen] = username.len() as u8;
    packetlen += 1;

    // MAC
    send_data[packetlen..packetlen + 6].copy_from_slice(mac);
    packetlen += mac.len();

    // IP
    send_data[packetlen..packetlen + 4].copy_from_slice(&local_ipaddr.octets());
    packetlen += 4;

    send_data[packetlen..packetlen + 4].copy_from_slice(&[0x02, 0x22, 0x00, 0x2a]);
    packetlen += 4;

    // Challenge
    send_data[packetlen..packetlen + 4].copy_from_slice(&recv_data[8..12]);
    packetlen += 4;

    // crc32 (will be filled later)
    let crc32_mock = [
        0xc7, 0x2f, 0x31, 0x01, 0x7e, /* this byte will be set 0 after crc32 */
        0x00, 0x00, 0x00,
    ];
    send_data[packetlen..packetlen + crc32_mock.len()].copy_from_slice(&crc32_mock);
    packetlen += crc32_mock.len();

    // username
    send_data[packetlen..packetlen + username.len()].copy_from_slice(username.as_bytes());
    packetlen += username.len();

    // hostname
    send_data[packetlen..packetlen + (32 - username.len())].copy_from_slice(hostname.as_bytes());
    packetlen += 32 - username.len();

    // fill 32 bytes with 0x00
    send_data[packetlen..packetlen + 32].copy_from_slice(&[0x00; 32]);
    packetlen += 32;

    // DNS
    send_data[packetlen..packetlen + 4].copy_from_slice(&dns_ipaddr.octets());
    packetlen += 4;
    // ignore the second and third 4 bytes (DNS)
    packetlen += 16;

    // 0x0060
    // unknown
    send_data[packetlen..packetlen + 4].copy_from_slice(&[0x94, 0x00, 0x00, 0x00]);
    packetlen += 4;
    // os major
    send_data[packetlen..packetlen + 4].copy_from_slice(&[0x06, 0x00, 0x00, 0x00]);
    packetlen += 4;
    // os minor
    send_data[packetlen..packetlen + 4].copy_from_slice(&[0x02, 0x00, 0x00, 0x00]);
    packetlen += 4;
    // os build
    send_data[packetlen..packetlen + 4].copy_from_slice(&[0xf0, 0x23, 0x00, 0x00]);
    packetlen += 4;

    // 0x0070
    // os unknown
    send_data[packetlen..packetlen + 4].copy_from_slice(&[0x02, 0x00, 0x00, 0x00]);
    packetlen += 4;

    // 64 bytes version
    send_data[packetlen..packetlen + version.len()].copy_from_slice(version);
    packetlen += version.len();

    // 68 bytes hash
    send_data[packetlen..packetlen + 68].copy_from_slice(&[0x00; 68]); // fill 0x00
    send_data[packetlen..packetlen + hash.len()].copy_from_slice(hash);
    packetlen += 64;
    if packetlen % 4 != 0 {
        packetlen += 4 - (packetlen % 4);
    }

    // fill the length field
    send_data[2] = (packetlen & 0xFF) as u8;
    send_data[3] = ((packetlen >> 8) & 0xFF) as u8;

    // fill the crc32 field
    let crc = crc32(&send_data[..packetlen]);

    // save the crc32 to the first 4 bytes of crc_md5_info
    crc_md5_info[..4].copy_from_slice(&crc.to_le_bytes());

    // finish crc32, set the 5th byte to 0x00
    send_data[28] = 0x00;

    packetlen
}

pub fn misc_heart_beat_01_type_setter(
    send_data: &mut [u8],
    drcom_package_id: &mut u8,
    drcom_misc1_flux: &[u8; 4],
) -> usize {
    send_data[..40].fill(0);

    let mut packetlen = 0;
    send_data[packetlen] = 0x07;
    packetlen += 1;
    send_data[packetlen] = *drcom_package_id;
    *drcom_package_id += 1;
    packetlen += 1;
    send_data[packetlen..packetlen + 6].copy_from_slice(&[0x28, 0x00, 0x0b, 0x01, 0xdc, 0x02]);
    packetlen += 6;

    send_data[packetlen..packetlen + 2].copy_from_slice(&[0x00, 0x00]);
    packetlen += 2;
    debug_assert_eq!(packetlen, 10);

    // don't know what 11..15 is
    send_data[16..20].copy_from_slice(drcom_misc1_flux);
    // so as 20..40 ...
    40
}

pub fn misc_heart_beat_01_type_immediate(
    drcom_package_id: &mut u8,
    drcom_misc1_flux: &[u8; 4],
) -> [u8; 40] {
    let mut send_data = [0u8; 40];
    send_data[0] = 0x07;
    send_data[1] = *drcom_package_id;
    *drcom_package_id += 1;
    send_data[2..8].copy_from_slice(&[0x28, 0x00, 0x0b, 0x01, 0xdc, 0x02]);
    send_data[16..20].copy_from_slice(drcom_misc1_flux);
    send_data
}

pub fn misc_heart_beat_03_type_setter(
    send_data: &mut [u8],
    recv_data: &[u8],
    drcom_package_id: &mut u8,
    local_ipaddr: Ipv4Addr,
) -> usize {
    send_data[..40].fill(0);

    let mut packetlen = 0;
    send_data[packetlen] = 0x07;
    packetlen += 1;
    send_data[packetlen] = *drcom_package_id;
    *drcom_package_id += 1;
    packetlen += 1;
    send_data[packetlen..packetlen + 6].copy_from_slice(&[0x28, 0x00, 0x0b, 0x03, 0xdc, 0x02]);
    packetlen += 6;

    send_data[packetlen..packetlen + 2].copy_from_slice(&[0x00, 0x00]);
    packetlen += 2;
    debug_assert_eq!(packetlen, 10);

    let mut drcom_misc3_flux = [0u8; 4];
    drcom_misc3_flux.copy_from_slice(&recv_data[16..20]);

    send_data[16..20].copy_from_slice(&drcom_misc3_flux);

    send_data[28..32].copy_from_slice(&local_ipaddr.octets());

    40
}

pub fn misc_heart_beat_03_type_immediate(
    recv_data: &[u8],
    drcom_package_id: &mut u8,
    local_ipaddr: Ipv4Addr,
) -> [u8; 40] {
    let mut send_data = [0u8; 40];
    send_data[0] = 0x07;
    send_data[1] = *drcom_package_id;
    *drcom_package_id += 1;
    send_data[2..8].copy_from_slice(&[0x28, 0x00, 0x0b, 0x03, 0xdc, 0x02]);
    send_data[16..20].copy_from_slice(&recv_data[16..20]);
    send_data[28..32].copy_from_slice(&local_ipaddr.octets());
    send_data
}

pub fn alive_heart_beat_type_setter(
    send_data: &mut [u8],
    crc_md5_info: &[u8; 16],
    tailinfo: &[u8; 16],
) -> usize {
    send_data.fill(0);
    let mut packetlen = 0;
    send_data[packetlen] = 0xff;
    packetlen += 1;

    // Fill crc_md5_info
    send_data[packetlen..packetlen + 16].copy_from_slice(crc_md5_info);
    packetlen += crc_md5_info.len();

    let zeros = [0x00, 0x00, 0x00];
    send_data[packetlen..packetlen + zeros.len()].copy_from_slice(&zeros);
    packetlen += zeros.len();

    // Fill tailinfo decode from MISC_3000
    send_data[packetlen..packetlen + tailinfo.len()].copy_from_slice(tailinfo);
    packetlen += tailinfo.len();

    // Time information
    let timeinfo = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let timeinfo_2 = (timeinfo as u16).to_le_bytes();

    let timeinfo_bytes = [(timeinfo & 0xff) as u8, ((timeinfo >> 8) & 0xff) as u8];
    send_data[packetlen..packetlen + timeinfo_bytes.len()].copy_from_slice(&timeinfo_bytes);
    packetlen += timeinfo_bytes.len();

    debug_assert_eq!(&timeinfo_2, &timeinfo_bytes);

    packetlen
}
