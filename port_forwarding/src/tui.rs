use std::io;
use std::time::Duration;
use std::sync::mpsc;
use aya::maps::{Array, HashMap, MapData};
use futures::StreamExt;


use crossterm::{
    event::{
        Event, EventStream,
        KeyCode, KeyEventKind, KeyEvent, KeyModifiers,
    },
};

use ratatui::{
    Frame,
    Terminal,
    backend::{Backend },
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
};

use port_forwarding_common::InterfaceState;
use crate::{
    ControlMessage,
    WorkerResponse,
};


use crate::cli;
use cli::commands_node::{
    execute_command, suggest_next_commands, CommandNode,
};

// ---------------------------------------------------------------
// Special words handled by the TUI itself (not the command tree)
// ---------------------------------------------------------------

// ---------------------------------------------------------------
// TUI application state
// ---------------------------------------------------------------
pub struct TuiApp {
    pub input: String,
    pub shell_lines: Vec<String>,    // Shell panel: prompt history + output
    pub stats_lines: Vec<String>,    // Network Status panel
    pub rules_lines: Vec<String>,    // Active Rules panel
    pub should_quit: bool,
}

impl TuiApp {
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
fn handle_enter( tui: &mut TuiApp,
                 command_tree: &CommandNode,
                 tx: &mpsc::Sender<ControlMessage>,
                 echo_show_to_shell: &mut bool,)
{
    let line: String = tui.input.drain(..).collect();
    let trimmed = line.trim();

    tui.push_shell(format!("> {}", trimmed));
    if trimmed.is_empty() {
        return;
    }

    match special_keyword(trimmed) {
        Some(SpecialAction::Quit) => {
            tui.should_quit = true;
        }
        Some(SpecialAction::Help) => {
            tui.push_shell(
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
                    tui.push_shell(format!("  ok: {msg}"));
                    // immediate Active Rules refresh
                    let _ = tx.send(ControlMessage::ShowRule);
                }
                Err(e) => {
                    tui.push_shell(format!("  err: {e}"));
                }
            }
        }
    }
}

//
// Process for the Users Key input
//
fn user_input_event( key: KeyEvent,
                     tui: &mut TuiApp,
                     command_tree: &CommandNode,
                     tx: &mpsc::Sender<ControlMessage>,
                     echo_show_to_shell: &mut bool,)
{
    if key.kind != KeyEventKind::Press { return; }

    if key.code == KeyCode::Char('c')
        && key.modifiers.contains(KeyModifiers::CONTROL)
    {
        tui.should_quit = true;
        return;
    }

    match key.code {
        KeyCode::Char(c) => tui.input.push(c),
        KeyCode::Backspace => { tui.input.pop(); }
        KeyCode::Esc => tui.should_quit = true,

        KeyCode::Tab => {
            let lines = suggest_next_commands(
                command_tree,
                tui.input.trim_end(),
            );
            for l in lines { tui.push_shell(l); }
        }

        KeyCode::Enter => handle_enter(tui, command_tree, tx, echo_show_to_shell),

        _ => {}
    }
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

pub fn ui(f: &mut Frame, tui: &TuiApp)
{
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
    let stats = Paragraph::new(tui.stats_lines.join("\n"))
        .block(Block::default().title(" Network Status ").borders(Borders::ALL));
    f.render_widget(stats, left_rows[0]);

    // Active Rules (bottom-left)
    let rules = Paragraph::new(tui.rules_lines.join("\n"))
        .block(Block::default().title(" Active Rules ").borders(Borders::ALL));
    f.render_widget(rules, left_rows[1]);

    // Shell (right) — show tail of shell_lines + the live input as the last line
    let shell_area = cols[1];
    let inner_h = shell_area.height.saturating_sub(2) as usize; // minus the 2 border lines
    let log_h   = inner_h.saturating_sub(1);                    // reserve 1 line for the prompt

    let start = tui.shell_lines.len().saturating_sub(log_h);
    let mut text = tui.shell_lines[start..].join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    text.push_str(&format!("> {}", tui.input));

    let shell = Paragraph::new(text)
        .block(
            Block::default()
                .title(" Shell ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        );
    f.render_widget(shell, shell_area);
}


fn format_stats(if_index: u32, s: &InterfaceState) -> Vec<String> {
    vec![
        format!("iface idx : {}", if_index),
        format!("{:#?}", s),
    ]
}


// ---------------------------------------------------------------
// TUI main loop
// ---------------------------------------------------------------
pub async fn
run_tuiapp<B: Backend> ( terminal: &mut Terminal<B>,
                         mut tui: TuiApp,
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
        terminal.draw(|f| ui(f, &tui))?;

        tokio::select! {

            // ----- Keyboard input -----
            maybe_evt = reader.next() => {
                let Some(Ok(evt)) = maybe_evt else { continue };
                if let Event::Key(key) = evt {
                    user_input_event( key, &mut tui, command_tree, &tx, &mut echo_show_to_shell,);
                }
            }


            // ----- 1s tick: stats poll + rules snapshot request -----
            _ = tick.tick() => {
                match stats_map.get(&if_index, 0) {
                    Ok(state) => {
                        tui.stats_lines = format_stats(if_index, &state);
                    }
                    Err(e) => {
                        tui.stats_lines = vec![format!("stats err: {e}")];
                    }
                }
                let _ = tx.send(ControlMessage::ShowRule);
            }


            // ----- 50ms tick: drain worker responses -----
            _ = resp_poll.tick() => {
                while let Ok(resp) = resp_rx.try_recv() {
                    match resp {
                        WorkerResponse::RuleList(rules) => {
                            tui.rules_lines = if rules.is_empty() {
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
                                    tui.push_shell("  (no active rules)".to_string());
                                } else {
                                    tui.push_shell(format!("  active rules ({}):", rules.len()));
                                    for (port, ip, tp, pkts) in &rules {
                                        tui.push_shell(format!(
                                            "    {} -> {}.{}.{}.{}:{}  ({} pkts)",
                                            port, ip[0], ip[1], ip[2], ip[3], tp, pkts
                                        ));
                                    }
                                }
                            }
                        }
                        WorkerResponse::Err(e) => {
                            tui.push_shell(format!("  worker err: {e}"));
                        }
                    }
                }
            }
        }

        if tui.should_quit { break; }
    }

    Ok(())
}