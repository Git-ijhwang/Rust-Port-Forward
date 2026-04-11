#![no_std]
#![no_main]

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{self, Ipv4Hdr},
    tcp::TcpHdr,
};

use aya_ebpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    maps::{LruHashMap, Array, HashMap},
    programs::XdpContext
};
use aya_log_ebpf::info;
use aya_ebpf::helpers::r#gen::{bpf_csum_update, bpf_csum_diff};

use core::{net::Ipv4Addr, num::Wrapping};
use port_forwarding_common::{
    ForwardRule, GlobalConfig, InterfaceState, SessionKey, SessionValue
};

use crate::verify::{PacketContext, ptr_at, verify_headers};
use crate::cksum::{update_ip_checksum, update_tcp_checksum};
use crate::ether::update_eth_header;
mod verify;
mod ether;
mod cksum;

#[map]
pub static INVERSE_MAP: LruHashMap<SessionKey, SessionValue> =
    LruHashMap::with_max_entries(1024, 0);

#[map]
static RULES: HashMap<u16, ForwardRule> = HashMap::with_max_entries(1024, 0);

#[map]
static IFACE_STATS: HashMap<u32, InterfaceState> = HashMap::with_max_entries(16, 0);

#[map]
pub static CONFIG: Array<GlobalConfig> = Array::with_max_entries(1, 0);

#[xdp]
pub fn port_forwarding(ctx: XdpContext) -> u32 {
    match try_port_forwarding(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}


#[inline(always)]
fn insert_inverse_mapping (ctx: &XdpContext, rule: *mut ForwardRule, packet: &PacketContext)
    -> Result<(), ()>
{
    let ip_hdr = unsafe {&mut * (packet.ip_hdr as *mut Ipv4Hdr)};

    let tcp_hdr_ptr = unsafe { ptr_at::<TcpHdr>(&ctx, packet.l4_hdr_start)?};
    let tcp_hdr = unsafe { &mut *tcp_hdr_ptr };
    let old_src_port = u16::from_be_bytes( (*tcp_hdr).source);

    let sess_key = SessionKey {
        target_ip: unsafe{ (*rule).target_ip},
        target_port: unsafe{ (*rule).target_port},
        ebpf_port: old_src_port,
    };

    let sess_val = SessionValue {
        orig_src_ip: ip_hdr.src_addr,
        orig_src_port: old_src_port,
    };

    if INVERSE_MAP.insert(&sess_key, &sess_val, 0).is_err(){
        return Err(());
    }

    Ok(())
}


fn try_restore_response(ctx: &XdpContext, packet: &PacketContext, config: &GlobalConfig)
    -> Result<u32, ()>
{
    let sess_key = SessionKey {
        target_ip: unsafe { (*packet.ip_hdr).src_addr},
        target_port: packet.sport,
        ebpf_port: packet.dport,
    };

    // let sess_val = 
    //     Some(v) => v,
    //     None => return Err(()), 
    // };

    let sess_val: &SessionValue =match unsafe {INVERSE_MAP.get(&sess_key) } {
        Some(v) => v,
        None => return Err(()), 
    };

    // 원래 IP/Port로 복원
    unsafe {
        let eth_hdr = &mut *(ctx.data() as *mut EthHdr);
        let ip_hdr =  &mut *(packet.ip_hdr as *mut Ipv4Hdr);
        let tcp_hdr =  &mut *ptr_at::<TcpHdr>(&ctx, packet.l4_hdr_start)?;

        let old_sip = ip_hdr.src_addr;
        let old_dip = ip_hdr.dst_addr;
        let old_sport = tcp_hdr.source;
        let old_dport = tcp_hdr.dest;

        ip_hdr.src_addr = [192, 168, 4, 146]; // 원래 서버 IP로 복원
        ip_hdr.dst_addr = sess_val.orig_src_ip;

        tcp_hdr.source = 80u16.to_be_bytes(); // 원래 서버 포트로 복원
        // tcp_hdr.dest = sess_key.target_port.to_be_bytes();

        // Checksum 업데이트
        update_ip_checksum(ip_hdr, old_sip, ip_hdr.src_addr, old_dip, ip_hdr.dst_addr);
        update_tcp_checksum(tcp_hdr, old_sip, ip_hdr.src_addr, old_dip, ip_hdr.dst_addr, old_sport, tcp_hdr.source);

        update_eth_header(eth_hdr, config);

    }
    Ok(xdp_action::XDP_TX)
}


fn try_port_forwarding(ctx: XdpContext) -> Result<u32, ()> {

    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let _len = (ctx.data_end() - ctx.data()) as u64;

    let eth = unsafe {ptr_at::<EthHdr>(&ctx, 0)}?;
    // let mut eth_type = u16::from_be(((*(eth))).ether_type);
    let eth_type = u16::from_be(unsafe { (*eth).ether_type });
    if eth_type != 0x0800 {
        // 잡음이 너무 많으니 로그를 잠시 끕니다. (블루투스, ARP 패스)
        return Ok(xdp_action::XDP_PASS);
    }

    // info!(&ctx, "Received packet on ifindex {}", ifindex);
    let packet: verify::PacketContext = match unsafe { verify_headers(&ctx)} {
        Ok(p) => p,
        Err(_) => return Ok(xdp_action::XDP_PASS),
    };

    let config = unsafe { CONFIG.get(0).ok_or(())? };
    let config = unsafe { &*config };

    if let Some(rule) =  RULES.get_ptr_mut(&packet.dport) {
        info!(&ctx, "Matched forwarding rule for port {}", packet.dport);

        if insert_inverse_mapping(&ctx, rule, &packet).is_err() {
            return Ok(xdp_action::XDP_PASS);
        }

        unsafe {
            let ip_hdr = &mut * (packet.ip_hdr as *mut Ipv4Hdr);


            // Save Old IPs
            let old_sip = ip_hdr.src_addr;
            let old_dip = ip_hdr.dst_addr;

            let new_sip: [u8; 4] = config.my_ip;
            let new_dip = (*rule).target_ip;

            //Update Ips
            ip_hdr.src_addr = new_sip;
            ip_hdr.dst_addr = new_dip;

            let tcp_hdr_ptr = ptr_at::<TcpHdr>(&ctx, packet.l4_hdr_start)?.as_mut().unwrap();

            let tcp_hdr = &mut *tcp_hdr_ptr;

            // Save Old Ports
            let old_port = (*tcp_hdr).dest;
            let new_port = (*rule).target_port.to_be_bytes();

            // Update Destination Port only
            (*tcp_hdr).dest = new_port;

            // 통계 업데이트
            (*rule).packets += 1;
            
            update_ip_checksum(ip_hdr, old_sip, new_sip, old_dip, new_dip);

            update_tcp_checksum(tcp_hdr, old_sip, new_sip, old_dip, new_dip, old_port, new_port);

            // 수정된 패킷을 인터페이스로 바로 다시 내보냄
            return Ok(xdp_action::XDP_TX);
        }
    }

    if let Ok(ret) = try_restore_response(&ctx, &packet, config) {
        info!(&ctx, "Faile to Restore response packet for session with target ");
        return Ok(xdp_action::XDP_TX);

    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
