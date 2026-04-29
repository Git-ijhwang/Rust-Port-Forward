use std::io;
use std::net::Ipv4Addr;
use std::thread;
use std::env;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::Context as _;
use aya::{include_bytes_aligned, Ebpf};
use aya::maps::{Array, HashMap, MapData};
use aya::programs::{Xdp, XdpFlags};

use clap::Parser;
use dotenvy::dotenv;
use nix::net::if_::if_nametoindex;

use crossterm::{
    event::{
        DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode, KeyEventKind,
        KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::StreamExt;
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
    Frame, Terminal,
};

#[rustfmt::skip]
use log::{debug, info};

use port_forwarding_common::{ForwardRule, GlobalConfig, InterfaceState};

mod cli;
use cli::commands_node::{
    build_command_tree, execute_command, suggest_next_commands, CommandNode,
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

// ---------------------------------------------------------------
// TUI application state
// ---------------------------------------------------------------

pub struct App {
    pub input: String,
    pub shell_lines: Vec<String>,    // Shell panel: prompt history + output
    pub stats_lines: Vec<String>,    // Network Status panel
    pub rules_lines: Vec<String>,    // Active Rules panel
    pub should_quit: bool,
}

impl App {
    pub fn new() -> Self {
        let mut s = Self {
            input: String::new(),
            shell_lines: Vec::new(),
            stats_lines: vec!["No data yet".into()],
            rules_lines: vec!["No active rules".into()],
            should_quit: false,
        };
        s.push_shell("System started.");
        s.push_shell("Type 'help' or press Tab for suggestions.");
        s
    }

    fn push_shell<S: Into<String>>(&mut self, line: S) {
        self.shell_lines.push(line.into());
        let len = self.shell_lines.len();
        if len > 500 {
            self.shell_lines.drain(0..len - 500);
        }
    }
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
// Special words handled by the TUI itself (not the command tree)
// ---------------------------------------------------------------

enum SpecialAction {
    Quit,
    Help,
    Show,
}

fn special_keyword(line: &str) -> Option<SpecialAction> {
    match line.trim() {
        "quit" | "exit" | "q" => Some(SpecialAction::Quit),
        "help" | "h" | "?"    => Some(SpecialAction::Help),
        "show"                => Some(SpecialAction::Show),
        _ => None,
    }
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

    let app = App::new();
    let res = run_app( &mut terminal, app,
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


fn handle_enter( app: &mut App,
                 command_tree: &CommandTree,
                 tx: &Sender<ControlMessage>,
                 echo_show_to_shell: &mut bool,)
{
    let line: String = app.input.drain(..).collect();
    let trimmed = line.trim();

    app.push_shell(format!("> {}", trimmed));
    if trimmed.is_empty() {
        return;
    }

    match special_keyword(trimmed) {
        Some(SpecialAction::Quit) => {
            app.should_quit = true;
        }
        Some(SpecialAction::Help) => {
            app.push_shell(
                "commands: add <Listen Port> <Target IP> <Target Port> | remove <Listen Port> | show | quit"
                    .to_string(),
            );
        }

        Some(SpecialAction::Show) => {
            *echo_show_to_shell = true;
            let _ = tx.send(ControlMessage::ShowRule);
        }

        None => {
            match execute_command(command_tree, trimmed, &tx) {
                Ok(msg) => {
                    app.push_shell(format!("  ok: {msg}"));
                    // immediate Active Rules refresh
                    let _ = tx.send(ControlMessage::ShowRule);
                }
                Err(e) => {
                    app.push_shell(format!("  err: {e}"));
                }
            }
        }
    }
}

//
// Process for the Users Key input
//
fn key_input_event( key: KeyEvent,
              app: &mut App,
              command_tree: &CommandTree,
              tx: &Sender<ControlMessage>,
              echo_show_to_shell: &mut bool,)
{
    let mut reader = EventStream::new();

    if let Event::Key(key) = evt {
        if key.kind != KeyEventKind::Press { return; }

        if key.code == KeyCode::Char('c')
            && key.modifiers.contains(KeyModifiers::CONTROL)
        {
            app.should_quit = true;
            return;
        }

        match key.code {
            KeyCode::Char(c) => app.input.push(c),
            KeyCode::Backspace => { app.input.pop(); }
            KeyCode::Esc => app.should_quit = true,

            KeyCode::Tab => {
                let lines = suggest_next_commands(
                    command_tree,
                    app.input.trim_end(),
                );
                for l in lines { app.push_shell(l); }
            }

            KeyCode::Enter => handle_enter(app, command_tree, tx, echo_show_to_shell),

            _ => {}
        }
    }
}
// ---------------------------------------------------------------
// TUI main loop
// ---------------------------------------------------------------

pub async fn run_app<B: Backend> ( terminal: &mut Terminal<B>,
                                   mut app: App,
                                   tx: mpsc::Sender<ControlMessage>,
                                   resp_rx: mpsc::Receiver<WorkerResponse>,
                                   mut stats_map: HashMap<MapData, u32, InterfaceState>,
                                   if_index: u32,
                                   command_tree: &CommandNode )
-> anyhow::Result<()>
where
    B::Error: Send + Sync + 'static,
{
    let mut reader = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(1000));
    let mut resp_poll = tokio::time::interval(Duration::from_millis(50));

    // When set, the next RuleList response is also echoed into the Shell panel.
    let mut echo_show_to_shell = false;

    // Kick off an initial snapshot so Active Rules isn't blank for ~1s
    let _ = tx.send(ControlMessage::ShowRule);

    loop {
        terminal.draw(|f| ui(f, &app))?;

        tokio::select! {

            // ----- Keyboard input -----
            maybe_evt = reader.next() => {
                let Some(Ok(evt)) = maybe_evt else { continue };
                if let Event::Key(key) = evt {
                    key_input_event( key, &mut app, command_tree, &tx, &mut echo_show_to_shell,);
                }
            }


            // ----- 1s tick: stats poll + rules snapshot request -----
            _ = tick.tick() => {
                match stats_map.get(&if_index, 0) {
                    Ok(state) => {
                        app.stats_lines = format_stats(if_index, &state);
                    }
                    Err(e) => {
                        app.stats_lines = vec![format!("stats err: {e}")];
                    }
                }
                let _ = tx.send(ControlMessage::ShowRule);
            }


            // ----- 50ms tick: drain worker responses -----
            _ = resp_poll.tick() => {
                while let Ok(resp) = resp_rx.try_recv() {
                    match resp {
                        WorkerResponse::RuleList(rules) => {
                            app.rules_lines = if rules.is_empty() {
                                vec!["(no active rules)".to_string()]
                            } else {
                                rules.iter().map(|(port, ip, tp, pkts)| {
                                    format!(
                                        "{} -> {}.{}.{}.{}:{}  ({} pkts)",
                                        port, ip[0], ip[1], ip[2], ip[3], tp, pkts
                                    )
                                }).collect()
                            };

                            if echo_show_to_shell {
                                echo_show_to_shell = false;
                                if rules.is_empty() {
                                    app.push_shell("  (no active rules)".to_string());
                                } else {
                                    app.push_shell(format!("  active rules ({}):", rules.len()));
                                    for (port, ip, tp, pkts) in &rules {
                                        app.push_shell(format!(
                                            "    {} -> {}.{}.{}.{}:{}  ({} pkts)",
                                            port, ip[0], ip[1], ip[2], ip[3], tp, pkts
                                        ));
                                    }
                                }
                            }
                        }
                        WorkerResponse::Err(e) => {
                            app.push_shell(format!("  worker err: {e}"));
                        }
                    }
                }
            }
        }

        if app.should_quit { break; }
    }
    Ok(())
}

fn format_stats(if_index: u32, s: &InterfaceState) -> Vec<String> {
    vec![
        format!("iface idx : {}", if_index),
        format!("{:#?}", s),
    ]
}

// ---------------------------------------------------------------
// UI: three-panel layout
//
//   ┌ Network Status ─┐┌ Shell ─────────────────┐
//   │                 ││ history                │
//   ├ Active Rules ───┤│ ...                    │
//   │                 ││ > <input>              │
//   └─────────────────┘└────────────────────────┘
//
// The input is rendered as the LAST line of the Shell panel.
// ---------------------------------------------------------------

pub fn ui(f: &mut Frame, app: &App) {
    let area = f.area();

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    let left_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(cols[0]);

    // Network Status (top-left)
    let stats = Paragraph::new(app.stats_lines.join("\n"))
        .block(Block::default().title(" Network Status ").borders(Borders::ALL));
    f.render_widget(stats, left_rows[0]);

    // Active Rules (bottom-left)
    let rules = Paragraph::new(app.rules_lines.join("\n"))
        .block(Block::default().title(" Active Rules ").borders(Borders::ALL));
    f.render_widget(rules, left_rows[1]);

    // Shell (right) — show tail of shell_lines + the live input as the last line
    let shell_area = cols[1];
    let inner_h = shell_area.height.saturating_sub(2) as usize; // minus the 2 border lines
    let log_h   = inner_h.saturating_sub(1);                    // reserve 1 line for the prompt

    let start = app.shell_lines.len().saturating_sub(log_h);
    let mut text = app.shell_lines[start..].join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    text.push_str(&format!("> {}", app.input));

    let shell = Paragraph::new(text)
        .block(
            Block::default()
                .title(" Shell ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        );
    f.render_widget(shell, shell_area);
}