// use std::collections::HashMap;

use anyhow::Context as _;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use nix::net::if_::if_nametoindex;
use port_forwarding_common::{InterfaceState, ForwardRule};

use tokio::signal;

use aya::{include_bytes_aligned, Ebpf};
use aya::maps::{HashMap, MapData};
use log::info;
use std::sync::mpsc;

use dotenvy::dotenv;
use std::env;
use aya::maps::Array;
use port_forwarding_common::GlobalConfig;
use std::net::Ipv4Addr;
use std::thread;

mod cli;

pub enum ControlMessage {
    // 새로운 룰 추가: [IP 주소, 타겟 포트]
    AddRule {
        target_ip: [u8; 4],
        target_port: u16,
    },
    // 특정 포트의 룰 삭제
    DeleteRule {
        target_port: u16,
    },
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlp3s0")]
    iface: String,
}

fn config_setup (ebpf: &mut Ebpf)
    -> Result<(), anyhow::Error>
{
    dotenv().ok();

    let parse_mac = |key: &str| -> [u8; 6] {
        let mut res = [0u8; 6];
        let s = env::var(key).expect("Missing env key");

        for (i, b) in s.split(":").map(|b| u8::from_str_radix(b, 16).unwrap()).enumerate() {
            res[i] = b;
        }

        println!("Parsed MAC for {}: {:02x?}", key, res);
        res
    };

    let config = GlobalConfig {
        gw_mac: parse_mac("GW_MAC"),
        my_mac: parse_mac("MY_MAC"),
        my_ip: env::var("MY_IP")?.parse::<Ipv4Addr>()?.octets(),
    };

    // Load the global config into the eBPF map
    let mut config_map: Array<_, GlobalConfig> =
        Array::try_from(ebpf.map_mut("GLOBAL_CONFIG")
            .ok_or(anyhow::anyhow!("Failed to get GLOBAL_CONFIG map"))?)?;
    
    // We only have one config, so we use index 0
    config_map.set(0, &config, 0)?;

    println!("Global Config loaded into eBPF map");
    Ok(())
}

fn recv_message (mut rules_map: HashMap<MapData, u16, ForwardRule>, rx: mpsc::Receiver<ControlMessage>)
    -> anyhow::Result<()>
{
    println!("Waiting for commands...");

    while let Ok(msg) = rx.recv() {
        match msg {
            //Add Rule
            ControlMessage::AddRule { target_ip, target_port } => {
                // let mut rules: HashMap<_, u16, ForwardRule> = 
                    // HashMap::try_from(ebpf.map_mut("RULES").ok_or(anyhow::anyhow!("Map not found"))?)?;
                
                let new_rule = ForwardRule {
                    target_ip,
                    target_port,
                    action: 1, // 활성화
                    ..Default::default()
                };
                
                rules_map.insert(target_port, new_rule, 0)?;
                println!("🚀 Rule Added: {}.{}.{}.{}:{}", target_ip[0], target_ip[1], target_ip[2], target_ip[3], target_port);
            }

            //Del Rule
            ControlMessage::DeleteRule { target_port } => {
                // let mut rules: HashMap<_, u16, ForwardRule> = 
                    // HashMap::try_from(ebpf.map_mut("RULES").ok_or(anyhow::anyhow!("Map not found"))?)?;

                rules_map.remove(&target_port)?;
                println!("🗑️ Rule Deleted: Port {}", target_port);
            }

            _ => {}
        }
    }

    Ok(())

}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    let if_index = if_nametoindex("wlp3s0").context("failed to get interface index")?;

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(include_bytes_aligned!(
        // concat!( env!("OUT_DIR"), "/port_forwarding")
        "../../target/bpfel-unknown-none/release/port_forwarding"
    ))?;

    let (tx, rx) = mpsc::channel::<ControlMessage>();

    let tx_for_cli = tx.clone();

    config_setup(&mut ebpf)?;

    cli::commands_node::cli_prompt(tx_for_cli);

    aya_log::EbpfLogger::init(&mut ebpf).context("failed to initialize eBPF logger")?;
    let Opt { ref iface } = opt;


    let rules_raw_map = ebpf.take_map("RULES")
    .ok_or(anyhow::anyhow!("RULES 맵을 찾을 수 없습니다"))?;

    let mut rules_map: HashMap<MapData, u16, ForwardRule> =
        HashMap::try_from(rules_raw_map)?;

    let handle = thread::spawn(move || {
        if let Err(e) = recv_message(rules_map, rx) {
            eprintln!("Error in message in receiver: {}", e);
        }
    });


    let program: &mut Xdp = ebpf.program_mut("port_forwarding").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut stats_map: HashMap<_, u32, InterfaceState> = HashMap::try_from(ebpf.map_mut("IFACE_STATS").unwrap())?;


    stats_map.insert(if_index, InterfaceState::default(), 0)?;
    info!("Initialized IFACE_STATS for index {}", if_index);

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    tokio::signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
