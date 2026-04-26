use network_types::{
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
};

// #[inline(always)]
// fn update_csum(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
//     // 1의 보수 합(One's Complement Sum) 연산
//     // 공식: ~HC' = ~(~HC + ~m + m')
//     let mut sum = (!old_csum as u32) + (!old_val as u32) + (new_val as u32);
    
//     // 32비트 합에서 발생한 캐리(Carry)를 하위 16비트로 반영
//     while (sum >> 16) != 0 {
//         sum = (sum & 0xFFFF) + (sum >> 16);
//     }
    
//     !(sum as u16)
// }

#[inline(always)]
fn fold32(sum: u32) -> u32 {
    let s = (sum & 0xFFFF) + (sum >> 16);
    (s & 0xFFFF) + (s >> 16)
}
 
#[inline(always)]
fn update_csum(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
    // 공식: ~HC' = ~(~HC + ~m + m')
    let sum = (!old_csum as u32) + (!old_val as u32) + (new_val as u32);
    !(fold32(sum) as u16)
}

// 32비트 값(IP 주소 등)을 16비트씩 나누어 업데이트하는 헬퍼
#[inline(always)]
fn update_csum_32(old_csum: u16, old_val: [u8; 4], new_val: [u8; 4])
    -> u16
{
    let old_low = u16::from_be_bytes([old_val[0], old_val[1]]);
    let old_high = u16::from_be_bytes([old_val[2], old_val[3]]);
    let new_low = u16::from_be_bytes([new_val[0], new_val[1]]);
    let new_high = u16::from_be_bytes([new_val[2], new_val[3]]);

    let csum = update_csum(old_csum, old_low, new_low);
    update_csum(csum, old_high, new_high)
}


#[inline(always)]
pub fn update_ip_checksum(
        ip_hdr: &mut Ipv4Hdr,
        old_sip: [u8; 4],
        new_sip: [u8; 4],
        old_dip: [u8; 4],
        new_dip: [u8; 4])
{
    let mut csum = u16::from_be_bytes( ip_hdr.check );
    
    // 1. 출발지 IP 변경분 반영
    csum = update_csum_32(csum, old_sip, new_sip);
    
    // 2. 목적지 IP 변경분 반영
    csum = update_csum_32(csum, old_dip, new_dip);
    
    ip_hdr.check = csum.to_be_bytes();
}

#[inline(always)]
pub fn update_tcp_checksum(
        tcp_hdr: &mut TcpHdr, 
        old_sip: [u8; 4], new_sip: [u8; 4], 
        old_dip: [u8; 4], new_dip: [u8; 4],
        old_dport: [u8; 2], new_dport: [u8; 2]
) {
    let mut csum = u16::from_be_bytes(tcp_hdr.check);

    // 1. 가상 헤더의 SIP 변경분 반영
    csum = update_csum_32(csum, old_sip, new_sip);
    
    // 2. 가상 헤더의 DIP 변경분 반영
    csum = update_csum_32(csum, old_dip, new_dip);
    
    // 3. TCP 헤더의 목적지 Port 변경분 반영
    let old_p = u16::from_be_bytes(old_dport);
    let new_p = u16::from_be_bytes(new_dport);
    csum = update_csum(csum, old_p, new_p);

    tcp_hdr.check = csum.to_be_bytes();
}