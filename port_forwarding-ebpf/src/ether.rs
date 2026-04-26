use network_types::eth::EthHdr;
use aya_ebpf::programs::XdpContext;
use port_forwarding_common::GlobalConfig;

#[inline(always)]
pub fn update_eth_header(eth: &mut EthHdr, config: &GlobalConfig) -> Result<(), ()> {
    // Copy MY_MAC -> src_addr, byte by byte
    eth.src_addr[0] = config.my_mac[0];
    eth.src_addr[1] = config.my_mac[1];
    eth.src_addr[2] = config.my_mac[2];
    eth.src_addr[3] = config.my_mac[3];
    eth.src_addr[4] = config.my_mac[4];
    eth.src_addr[5] = config.my_mac[5];
 
    // Copy GW_MAC -> dst_addr, byte by byte
    eth.dst_addr[0] = config.gw_mac[0];
    eth.dst_addr[1] = config.gw_mac[1];
    eth.dst_addr[2] = config.gw_mac[2];
    eth.dst_addr[3] = config.gw_mac[3];
    eth.dst_addr[4] = config.gw_mac[4];
    eth.dst_addr[5] = config.gw_mac[5];
 
    Ok(())
}