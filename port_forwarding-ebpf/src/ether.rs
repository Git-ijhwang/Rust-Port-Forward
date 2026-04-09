const GW_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]; // 실제 AP MAC으로 수정
const MY_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]; // 내 기기 MAC

#[inline(always)]
fn update_eth_header(ctx: &XdpContext, eth: &mut EthHdr) -> Result<(), ()> {

    // MAC 주소 업데이트 (예시로 고정된 MAC 주소 사용)
    let new_src_mac = [0x00, 0x0c, 0x29, 0x3e, 0x5c, 0x7d]; // 예시로 사용할 새로운 MAC 주소
    let new_dst_mac = [0x00, 0x50, 0x56, 0xe4, 0x12, 0x34]; // 예시로 사용할 새로운 MAC 주소

    eth.src_mac = new_src_mac;
    eth.dst_mac = new_dst_mac;

    Ok(())
}