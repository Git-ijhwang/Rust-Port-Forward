use std::io;
use std::net::Ipv4Addr;
use std::thread;
use std::env;
use std::sync::mpsc;

use anyhow::Context as _;
use aya::{include_bytes_aligned, Ebpf};
use aya::maps::{Array, HashMap, MapData};
use aya::programs::{Xdp, XdpFlags};

use clap::Parser;
use dotenvy::dotenv;
use nix::net::if_::if_nametoindex;

use crossterm::{
    execute,
    event::{
        DisableMouseCapture, EnableMouseCapture,
    },
    terminal::{
        disable_raw_mode, enable_raw_mode,
        EnterAlternateScreen, LeaveAlternateScreen
    },
};
use ratatui::{
    Terminal,
    backend::{Backend, CrosstermBackend},
};

#[rustfmt::skip]
use log::{debug, info};

use port_forwarding_common::{ForwardRule, GlobalConfig, InterfaceState};

mod cli;
use cli::commands_node::{ build_command_tree };

mod tui;
use tui::{
    run_tuiapp,
    TuiApp,
};

// ---------------------------------------------------------------
// Channel messages
// ---------------------------------------------------------------

/// TUI -> worker
pub enum ControlMessage {
    AddRule {listen_port:u16, target_ip: [u8; 4], target_port: u16 },
    DeleteRule { listen_port: u16 },
    ShowRule,
}

/// worker -> TUI
pub enum WorkerResponse {
    /// Snapshot of all current rules. (listen_port, target_ip, target_port, packets)
    RuleList(Vec<(u16, [u8; 4], u16, u64)>),
    /// Worker-side error to display in the Shell.
    Err(String),
}


#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlp3s0")]
    iface: String,
}

// ---------------------------------------------------------------
// Global config setup
// ---------------------------------------------------------------

fn config_setup(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    dotenv().ok();

    let parse_mac = |key: &str| -> [u8; 6] {
        let mut res = [0u8; 6];
        let s = env::var(key).expect("Missing env key");
        for (i, b) in s.split(':').map(|b| u8::from_str_radix(b, 16).unwrap()).enumerate() {
            res[i] = b;
        }
        res
    };

    let config = GlobalConfig {
        gw_mac: parse_mac("GW_MAC"),
        my_mac: parse_mac("MY_MAC"),
        my_ip:  env::var("MY_IP")?.parse::<Ipv4Addr>()?.octets(),
    };

    let mut config_map: Array<_, GlobalConfig> = Array::try_from(
        ebpf.map_mut("CONFIG")
            .ok_or_else(|| anyhow::anyhow!("Failed to get GLOBAL_CONFIG map"))?,
    )?;

    // let mut config_map: Array<_, GlobalConfig> =
    //     Array::try_from(ebpf.map_mut("CONFIG")
    //         .ok_or(anyhow::anyhow!("Failed to get GLOBAL_CONFIG map"))?)?;

    config_map.set(0, &config, 0)?;
    Ok(())
}


// ---------------------------------------------------------------
// Worker thread
// ---------------------------------------------------------------

fn recv_message( mut rules_map: HashMap<MapData, u16, ForwardRule>,
                 cmd_rx: mpsc::Receiver<ControlMessage>,
                 resp_tx: mpsc::Sender<WorkerResponse>,)
-> anyhow::Result<()>
{
    while let Ok(msg) = cmd_rx.recv() {
        match msg {
            ControlMessage::AddRule {listen_port, target_ip, target_port } => {
                let new_rule = ForwardRule {
                    target_ip,
                    target_port,
                    action: 1,
                    ..Default::default()
                };
                if let Err(e) = rules_map.insert(listen_port, new_rule, 0) {
                    let _ = resp_tx.send(WorkerResponse::Err(format!("insert failed: {e}")));
                }
            }

            ControlMessage::DeleteRule { listen_port } => {
                if let Err(e) = rules_map.remove(&listen_port) {
                    let _ = resp_tx.send(WorkerResponse::Err(format!("remove failed: {e}")));
                }
            }

            ControlMessage::ShowRule => {
                let mut rules: Vec<(u16, [u8; 4], u16, u64)> = Vec::new();
                for entry in rules_map.iter() {
                    if let Ok((port, rule)) = entry {
                        rules.push((port, rule.target_ip, rule.target_port, rule.packets));
                    }
                }
                rules.sort_by_key(|(p, _, _, _)| *p);
                let _ = resp_tx.send(WorkerResponse::RuleList(rules));
            }
        }
    }
    Ok(())
}


// ---------------------------------------------------------------
// main
// ---------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    env_logger::init();

    let if_index = if_nametoindex("wlp3s0").context("failed to get interface index")?;
    // let if_index = if_nametoindex(opt.iface.as_str())
        // .context("failed to get interface index")?;

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/port_forwarding"
    ))?;

    config_setup(&mut ebpf)?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        info!("eBPF logger not initialized: {e}");
    }

    let program: &mut Xdp = ebpf.program_mut("port_forwarding").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&opt.iface, XdpFlags::SKB_MODE)
        .context("failed to attach XDP (SKB_MODE)")?;

    {
        let mut stats_map: HashMap<_, u32, InterfaceState> =
            HashMap::try_from(ebpf.map_mut("IFACE_STATS").unwrap())?;
        stats_map.insert(if_index, InterfaceState::default(), 0)?;
        info!("Initialized IFACE_STATS for index {}", if_index);
    }

    let stats_raw = ebpf
        .take_map("IFACE_STATS")
        .ok_or_else(|| anyhow::anyhow!("IFACE_STATS map missing"))?;

    let stats_map: HashMap<MapData, u32, InterfaceState> = HashMap::try_from(stats_raw)?;

    let rules_raw = ebpf
        .take_map("RULES")
        .ok_or_else(|| anyhow::anyhow!("RULES map missing"))?;
    let rules_map: HashMap<MapData, u16, ForwardRule> = HashMap::try_from(rules_raw)?;

    //Channel Creation
    let (cmd_tx,  cmd_rx)  = mpsc::channel::<ControlMessage>();
    let (resp_tx, resp_rx) = mpsc::channel::<WorkerResponse>();

    /*
        Spawn worker thread to receive TUI commands and interact with eBPF maps.
    */
    let _worker = thread::spawn(move || {
        if let Err(e) = recv_message(rules_map, cmd_rx, resp_tx) {
            eprintln!("recv_message error: {e}");
        }
    });

    let _ebpf_guard = ebpf;
    let command_tree = build_command_tree();

    enable_raw_mode()?;

    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let tui = TuiApp::new();
    let res = run_tuiapp( &mut terminal, tui,
                                            cmd_tx, resp_rx,
                                            stats_map, if_index,
                                            &command_tree,)
        .await;

    disable_raw_mode()?;

    execute!( terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    if let Err(e) = res {
        eprintln!("TUI error: {e}");
    }

    Ok(())
}


