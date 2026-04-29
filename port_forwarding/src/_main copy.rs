// use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::thread;
use std::env;
use std::sync::mpsc;
use std::time::Duration;
use std::io;

use anyhow::Context as _;
use aya::{include_bytes_aligned, Ebpf};
use aya::maps::{Array, HashMap, MapData};
use aya::programs::{Xdp, XdpFlags};
// use tokio::macros::select;
use tokio::select;
use tokio::signal;

use clap::Parser;

#[rustfmt::skip]
use log::{debug, warn};

use nix::net::if_::if_nametoindex;
use log::info;
use dotenvy::dotenv;
use futures::StreamExt;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
    Frame, Terminal,
};

use port_forwarding_common::{InterfaceState, ForwardRule};
use port_forwarding_common::GlobalConfig;

use crate::cli::commands_node::{execute_command, suggest_next_commands, build_command_tree,  CommandNode};

mod cli;

pub struct App {
    pub input: String,
    pub logs: Vec<String>,
    pub stats_lines: Vec<String>,
    pub should_quit: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            input: String::new(),
            logs: vec!["System started ...".into()],
            stats_lines: vec!["No data yet".into()],
            should_quit: false,
        }
    }

    fn push_log<S: Into<String>>(&mut self, line: S) {
        self.logs.push(line.into());
        // keep last 200 lines
        let len = self.logs.len();
        if len > 200 {
            self.logs.drain(0..len - 200);
        }
    }
}

pub enum ControlMessage {
    // 새로운 룰 추가: [IP 주소, 타겟 포트]
    AddRule {
        listen_port: u16,
        target_ip: [u8; 4],
        target_port: u16,
    },
    // 특정 포트의 룰 삭제
    DeleteRule {
        listen_port: u16,
    },

    ShowRule {
        // listen_port: u16,
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
        Array::try_from(ebpf.map_mut("CONFIG")
            .ok_or(anyhow::anyhow!("Failed to get GLOBAL_CONFIG map"))?)?;
    
    // We only have one config, so we use index 0
    config_map.set(0, &config, 0)?;

    println!("Global Config loaded into eBPF map");
    Ok(())
}


fn recv_message (mut rules_map: HashMap<MapData, u16, ForwardRule>, rx: mpsc::Receiver<ControlMessage>)
    -> anyhow::Result<()>
{
    while let Ok(msg) = rx.recv() {
        match msg {
            //Add Rule
            ControlMessage::AddRule {listen_port,  target_ip, target_port } => {
                
                let new_rule = ForwardRule {
                    // listen_port,
                    target_ip,
                    target_port,
                    action: 1, // 활성화
                    ..Default::default()
                };
                
                rules_map.insert(listen_port, new_rule, 0)?;
                println!("🚀 Rule Added: {}.{}.{}.{}:{}", target_ip[0], target_ip[1], target_ip[2], target_ip[3], target_port);
            }

            //Del Rule
            ControlMessage::DeleteRule { listen_port } => {
                // let mut rules: HashMap<_, u16, ForwardRule> = 
                    // HashMap::try_from(ebpf.map_mut("RULES").ok_or(anyhow::anyhow!("Map not found"))?)?;

                rules_map.remove(&listen_port)?;
                println!("🗑️ Rule Deleted: Port {}", target_port);
            }

            //Show Rule
            ControlMessage::ShowRule {  } => {
                let rules = rules_map.iter().map(|(port, rule)| format!("Port {} -> {}.{}.{}.{}:{}", port, rule.target_ip[0], rule.target_ip[1], rule.target_ip[2], rule.target_ip[3], rule.target_port)).collect::<Vec<_>>().join("\n");
                println!("Show Rules {:#?}", rules);
            }

            _ => {}
        }
    }

    Ok(())

}

enum ParsedCmd {
    Ctrl(ControlMessage),
    Quit,
    Info(String),
    Err(String),
}


fn parse_cmd(line: &str) -> ParsedCmd {
    let mut it = line.split_whitespace();
    match it.next() {
        Some("add") => {
            let ip_s = match it.next() {
                Some(s) => s,
                None => return ParsedCmd::Err("usage: add <ip> <port>".into()),
            };
            let port_s = match it.next() {
                Some(s) => s,
                None => return ParsedCmd::Err("usage: add <ip> <port>".into()),
            };
            let ip: Ipv4Addr = match ip_s.parse() {
                Ok(v) => v,
                Err(_) => return ParsedCmd::Err(format!("bad ip: {ip_s}")),
            };
            let port: u16 = match port_s.parse() {
                Ok(v) => v,
                Err(_) => return ParsedCmd::Err(format!("bad port: {port_s}")),
            };
            ParsedCmd::Ctrl(ControlMessage::AddRule {
                target_ip: ip.octets(),
                target_port: port,
            })
        }
        Some("del") | Some("rm") => {
            let port_s = match it.next() {
                Some(s) => s,
                None => return ParsedCmd::Err("usage: del <port>".into()),
            };
            let port: u16 = match port_s.parse() {
                Ok(v) => v,
                Err(_) => return ParsedCmd::Err(format!("bad port: {port_s}")),
            };
            ParsedCmd::Ctrl(ControlMessage::DeleteRule { target_port: port })
        }
        Some("quit") | Some("exit") | Some("q") => ParsedCmd::Quit,
        Some("help") | Some("h") | Some("?") => ParsedCmd::Info(
            "commands: add <ip> <port> | del <port> | quit".into(),
        ),
        Some(other) => ParsedCmd::Err(format!("unknown command: {other}")),
        None => ParsedCmd::Info(String::new()),
    }
}


// ---------------------------------------------------------------
// Keywords the tree does not handle: quit/help
// ---------------------------------------------------------------
enum SpecialAction {
    Quit,
    Help,
}
 
fn special_keyword(line: &str) -> Option<SpecialAction> {
    match line.trim() {
        "quit" | "exit" | "q" => Some(SpecialAction::Quit),
        "help" | "h" | "?"    => Some(SpecialAction::Help),
        _ => None,
    }
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

    // - let tx_for_cli = tx.clone();

    config_setup(&mut ebpf)?;

    // - cli::commands_node::cli_prompt(tx_for_cli);

    // aya_log::EbpfLogger::init(&mut ebpf).context("failed to initialize eBPF logger")?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf){
        info!("eBPF logger not initialized: {e}");
    }

    // - let Opt { ref iface } = opt;


    let program: &mut Xdp = ebpf.program_mut("port_forwarding").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    {
        let mut stats_map: HashMap<_, u32, InterfaceState> = HashMap::try_from(ebpf.map_mut("IFACE_STATS").unwrap())?;
        stats_map.insert(if_index, InterfaceState::default(), 0)?;
        info!("Initialized IFACE_STATS for index {}", if_index);
    }

    let stats_raw = ebpf
        .take_map("IFACE_STATS")
        .ok_or_else(|| anyhow::anyhow!("IFACE_STATS map missing"))?;
    let stats_map: HashMap<MapData, u32, InterfaceState> = HashMap::try_from(stats_raw)?;


    let rules_raw = ebpf
        .take_map("RULES")
        .ok_or_else(|| anyhow::anyhow!("RULES 맵을 찾을 수 없습니다"))?;
    let mut rules_map: HashMap<MapData, u16, ForwardRule> =
        HashMap::try_from(rules_raw)?;

    let (tx, rx) = mpsc::channel::<ControlMessage>();

    let worker = thread::spawn(move || {
        if let Err(e) = recv_message(rules_map, rx) {
            eprintln!("Error in message in receiver: {}", e);
        }
    });

    let _ebpf_guard = ebpf;

    let command_tree = build_command_tree();

    // ---- TUI ----
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;



    let app = App::new();
    let res = run_app(&mut terminal, app, tx, stats_map, if_index, &command_tree).await;

    // restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
 
    if let Err(e) = res {
        eprintln!("TUI error: {e}");
    }
 
    // worker will exit when tx drops (end of this function)
    drop(worker); // detach; thread exits as channel closes
 

    // let ctrl_c = signal::ctrl_c();
    // println!("Waiting for Ctrl-C...");
    // tokio::signal::ctrl_c().await?;
    // println!("Exiting...");

    Ok(())
}


pub async fn run_app <B: Backend> (
    terminal: &mut Terminal<B>,
    mut app: App,
    tx: mpsc::Sender<ControlMessage>,
    mut stats_map: HashMap<MapData, u32, InterfaceState>,
    if_index: u32,
    command_tree: &CommandNode,
) -> anyhow::Result<()>
where
    B::Error: Send + Sync + 'static,
{
    let mut reader = EventStream::new();
    let mut stats_interval = tokio::time::interval(Duration::from_millis(500));

    loop {
        terminal.draw(|f| ui(f, &app))?;

        select! {
            // Some(Ok(evt))
            maybe_evt = reader.next() => {

                let Some(Ok(evt)) = maybe_evt else { continue; };

                if let Event::Key(key) = evt {
                    if key.kind != KeyEventKind::Press { continue; }

                    if key.code == KeyCode::Char('c')
                        && key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL)
                    {
                        app.should_quit = true;
                        continue;
                    }

                    match key.code {
                        KeyCode::Char(c) => app.input.push(c),
                        KeyCode::Backspace => { app.input.pop(); },
                        KeyCode::Esc => app.should_quit = true,

                        KeyCode::Tab => {
                            let lines = suggest_next_commands(command_tree, app.input.trim_end());
                            for l in lines {
                                app.push_log(format!("  {l}"));
                            }
                        }

                        KeyCode::Enter => {
                            let line: String = app.input.drain(..).collect();
                            let trimmed = line.trim();

                            if trimmed.is_empty() {
                                // write!(stdout, "\n\r> ").unwrap();
                            } else {
                                app.push_log(format!("> {}", trimmed));

                                match special_keyword(trimmed) {
                                    Some(SpecialAction::Quit) => {
                                        app.should_quit = true;
                                        // continue;
                                    }
                                    Some(SpecialAction::Help) => {
                                        app.push_log("Available commands: add <ip> <port>, del <port>, quit");
                                        // continue;
                                    }
                                    None => {
                                        match execute_command(&command_tree, trimmed, &tx) {
                                            Ok(msg) => app.push_log(format!("Ok:  {msg}")),
                                            Err(e) => app.push_log(format!("Err: {e}")),
                                        }
                                    }
                                }

                                // match parse_cmd(trimmed) {
                                //     ParsedCmd::Ctrl(msg) => {
                                //         let desc = match &msg {
                                //             ControlMessage::AddRule { target_ip, target_port } =>
                                //                 format!("ADD {}.{}.{}.{}:{}",
                                //                     target_ip[0], target_ip[1],
                                //                     target_ip[2], target_ip[3],
                                //                     target_port),
                                //             ControlMessage::DeleteRule { target_port } =>
                                //                 format!("DEL port {}", target_port),
                                //         };
                                //         match tx.send(msg) {
                                //             Ok(_)  => app.push_log(format!("  ok: {desc}")),
                                //             Err(e) => app.push_log(format!("  send err: {e}")),
                                //         }
                                //     }
                                //     ParsedCmd::Quit => app.should_quit = true,
                                //     ParsedCmd::Info(s) => if !s.is_empty() { app.push_log(s); },
                                //     ParsedCmd::Err(e) => app.push_log(format!("  err: {e}")),

                                // }
                            }

                            // else if input == "exit" || input == "quit" || input == "q"  {
                            //     writeln!(stdout, "\n\rExiting command interface.").unwrap();
                            //     break;
                            // }
                            // else {
                            //     writeln!(stdout, "\n\rExecuting command: {}", input).unwrap();
                            //     execute_command(&command_tree, input.as_str(), &tx);
                            //     input.clear();
                            // }
                            // write!(stdout, "\r> ").unwrap();
                        }
                        _ => {}
                    }
                }
            }

            _ = stats_interval.tick() => {
                match stats_map.get(&if_index, 0) {
                    Ok(state) => {
                        app.stats_lines = format_stats(if_index, &state);
                    }
                    Err(e) => {
                        app.stats_lines = vec![format!("Failed to read stats: {e}")];  
                    }
                }
            }
        }

        if app.should_quit {break;}
    }
    Ok(())
}

fn format_stats(if_index: u32, s: &InterfaceState) -> Vec<String> {
    vec![
        format!("Interface idx: {}", if_index),
        format!("{:#?}", s),
    ]
}

pub fn ui(f: &mut ratatui::Frame, app: &App) {

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)]) // 메인 영역과 입력창
        .split(f.area());

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)]) // 통계와 로그
        .split(chunks[0]);

    // 1. Stats Panel
    let stats = Paragraph::new(app.stats_lines.join("\n"))
        .block(Block::default().title(" Network Statu s").borders(Borders::ALL));
    f.render_widget(stats, main_chunks[0]);


    // show the tail of the logs so newest lines stay visible
    let log_area_h = main_chunks[1].height.saturating_sub(2) as usize;
    let start = app.logs.len().saturating_sub(log_area_h);
    let log_text = app.logs[start..].join("\n");
    let logs = Paragraph::new(log_text)
        .block(Block::default().title(" Sessions & Logs ").borders(Borders::ALL));
    f.render_widget(logs, main_chunks[1]);
 
    // 2. Log Panel
    // let logs = Paragraph::new(app.logs.join("\n"))
        // .block(Block::default().title(" Sessions & Logs ").borders(Borders::ALL));
    // f.render_widget(logs, main_chunks[1]);

    // 3. CLI Input Panel
    let input = Paragraph::new(app.input.as_str())
        .block(Block::default().title(" Command CLI ").borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow)));
    f.render_widget(input, chunks[1]);
}