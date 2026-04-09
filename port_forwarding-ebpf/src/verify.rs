use network_types::{eth::{EthHdr, EtherType}, ip::{Ipv4Hdr, IpProto}, tcp::TcpHdr, udp::UdpHdr};
use core::mem;
use aya_log_ebpf::info;
// use crate::XdpContext;
use aya_ebpf::programs::XdpContext;

pub enum L4Protocol {
    Tcp, Udp
}

pub struct PacketContext {
    pub ip_hdr: *mut Ipv4Hdr,     // 수정을 위해 mut 포인터 사용
    pub proto: L4Protocol,
    pub dport: u16,               // 목적지 포트 (Host 엔디안)
    pub sport: u16,               // 목적지 포트 (Host 엔디안)
    pub l4_hdr_start: usize,      // L4 헤더가 시작되는 위치(오프셋)
}

#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &aya_ebpf::programs::XdpContext, offset: usize)
    -> Result<*mut T, ()>
{
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset+ len > end {
        return Err(());
    }

    Ok((start+offset) as *mut T)
}

#[inline(always)]
pub unsafe fn verify_headers(ctx: &XdpContext)
    -> Result<PacketContext, ()>
{
    let mut offset = 0;

    // 1. Ethernet 파싱
    let eth = unsafe {ptr_at::<EthHdr>(ctx, offset)?};
    let mut eth_type = u16::from_be((*eth).ether_type);
    // offset += 14; // Ethernet 헤더 크기
    offset += mem::size_of::<EthHdr>();


    // VLAN 처리
    if eth_type == 0x8100 {
        let next_proto = unsafe {ptr_at::<u16>(ctx, 14 + 2)?};
        eth_type = u16::from_be(*next_proto);
        offset += 4;
    }

    if eth_type != 0x0800 {
        return Err(());
    }

    // 2. IPv4 파싱
    let ip = unsafe { ptr_at::<Ipv4Hdr>(ctx, offset)?};
    let ip_len = (*ip).ihl() as usize; //ihl()은 이미 <<2 연산이 적용됨.
    if ip_len < 20 { return Err(()); }
    let l4_offset = offset + ip_len;

    // 3. L4 프로토콜 확인
    match (*ip).proto {
        IpProto::Tcp => {
            let tcp = unsafe {ptr_at::<TcpHdr>(ctx, l4_offset)?};
            Ok(PacketContext {
                ip_hdr: ip,
                proto: L4Protocol::Tcp,
                // network-types 크레이트 버전에 따라 필드명이 다를 수 있으니 주의
                dport: u16::from_be_bytes((*tcp).dest), 
                sport: u16::from_be_bytes((*tcp).source), 
                l4_hdr_start: l4_offset,
            })
        }
        IpProto::Udp => {
            let udp = unsafe { ptr_at::<UdpHdr>(ctx, l4_offset)? };
            Ok(PacketContext {
                ip_hdr: ip,
                proto: L4Protocol::Udp,
                dport: u16::from_be_bytes((*udp).dst), // dst -> dest 일관성 확인
                sport: u16::from_be_bytes((*udp).src), // src -> source 일관성 확인
                l4_hdr_start: l4_offset,
            })
        }
        _ => {
            info!(ctx, "Unsupported L4 protocol:");
            Err(())
        },
    }
}