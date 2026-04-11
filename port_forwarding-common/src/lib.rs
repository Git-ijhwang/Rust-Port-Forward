#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ForwardRule {
    pub target_ip: [u8; 4],
    pub target_port: u16,
    pub action: u32,      // 0: Pass, 1: Drop/Count
    pub packets: u64,
    pub bytes: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct InterfaceState {
    pub rx_packets: u64,
    pub rx_bytes: u64,
}

// 유저 스페이스(aya)에서만 사용되는 트레이트 구현
#[cfg(feature = "user")]
unsafe impl aya::Pod for ForwardRule {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for InterfaceState {}


#[repr(C)]
#[derive(Clone, Copy)]
pub struct SessionKey {
    pub target_ip: [u8; 4],   // 응답을 보내는 서버의 IP (192.168.4.131)
    pub target_port: u16,    // 응답을 보내는 서버의 포트 (8080)
    pub ebpf_port: u16,      // 클라이언트가 원래 접속했던 포트 (80) 또는 클라이언트의 ephemeral port
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SessionValue {
    pub orig_src_ip: [u8; 4], // 원래 클라이언트 IP (192.168.4.111)
    pub orig_src_port: u16,   // 원래 클라이언트 포트
}

// 오프셋 계산 등에서 안전하게 사용하기 위해 수동으로 구현하거나 
// aya-ebpf의 필터링을 위해 기본값을 정의할 수 있습니다.
#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionValue {}


/* Configurations */
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GlobalConfig {
    pub gw_mac: [u8; 6],      // Gateway(AP) MAC
    pub my_ip: [u8; 4],       // eBPF 기기 IP
    pub service_port: u16,    // 서비스 포트 (예: 80)
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for GlobalConfig {}