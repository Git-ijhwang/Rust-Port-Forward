use network_types::eth::EthHdr;
use aya_ebpf::programs::XdpContext;

const GW_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]; // 실제 AP MAC으로 수정
const MY_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]; // 내 기기 MAC

#[inline(always)]
fn update_eth_header(ctx: &XdpContext, eth: &mut EthHdr) -> Result<(), ()> {

    // MAC 주소 업데이트 (예시로 고정된 MAC 주소 사용)
    eth.src_addr = MY_MAC;
    eth.dst_addr = GW_MAC;

    Ok(())
}