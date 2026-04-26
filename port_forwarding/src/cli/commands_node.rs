use std::hash::Hash;
use std::thread;
use std::collections::HashMap;
use std::io::{Stdin, Stdout};
use std::io::{self, Write};
use clap::Arg;
use termion::raw::IntoRawMode;
use termion::event::{Event, Key};
use termion::input::TermRead;

use std::sync::mpsc;

use crate::ControlMessage;
use crate::cli::command;

type ActionFn = fn(Vec<String>, &mpsc::Sender<ControlMessage>)->Result<String, String>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ArgType {
    Command,
    Ip,
    Port
}

#[derive(Debug, Clone)]
pub struct CommandNode {
    command:        String,
    description:    String,
    subcommands:    HashMap<String, CommandNode>,
    arg_type:       Option<ArgType>,
    value_child:    Option<Box<CommandNode>>,

    action:         Option<ActionFn>, // 실행할 함수, 필요 시 추가 파라미터 포함
}
impl CommandNode {
    fn new(
        command: &str,
        description: &str,
        arg_type: Option<ArgType>,//&str,
        value_child: Option<Box<CommandNode>>,
        action: Option<ActionFn>) -> Self
    {
        Self {
            command:     command.to_string(),
            description: description.to_string(),
            subcommands: HashMap::new(),
            arg_type,
            value_child,
            action,
        }
    }

	fn insert(&mut self, command: command::Command) -> bool{

		if command.parent == self.command {
            // println!("!Current node: {}, Command parent: {}", self.command, command.parent);

            let argtype = match command.arg_type.as_str() {
                "Command"  => Some(ArgType::Command),
                "Ip" => Some(ArgType::Ip),
                "Port" => Some(ArgType::Port),
                _ => None,
            };

			let node = CommandNode::new(&command.command,
                    &command.description,
                    argtype,
                    // &command.arg_type,
                    None,
                    command.action);

            if command.arg_type ==  "Command" {
                self.subcommands.insert( command.command.clone(), node);
            }
            else {
                self.value_child = Some(Box::new(node));
            }

            return true;
		}

        for child in self.subcommands.values_mut() {
            child.insert(command.clone());
            return true;
        }

        if let Some(child) = self.value_child.as_mut() {
            child.insert(command);
            return true;
        }

        return false;
	}

}


fn find_node<'a>(node: &'a CommandNode, parts: &[&str]) -> Option<&'a CommandNode> {
    let mut current = node;

    println!("Current command : {}", current.command);
    for part in parts {
        if  current.subcommands.len() > 0 {
            match current.subcommands.get(*part) {
                Some(child) => current = child,
                None => return None,
            }
            // println!("Current {:#?}", current);
        }
        else {
            // println!("Current node has no subcommands, checking for value child...");
            if let Some(value_child) = &current.value_child {
                current = value_child;
                // println!("Current value child: {:#?}", current);
            }
            else {
                println!("\rNo suggestions found.");
                return None;
            }
        }
    }

    Some(current)
}

fn validate_command(arg: &str, arg_type: Option<ArgType>) -> bool {
    let ret = match arg_type {
        Some(ArgType::Ip) => arg.parse::<std::net::Ipv4Addr>().is_ok(),
        Some(ArgType::Port) => arg.parse::<u16>().is_ok(),
        _ => true, // For "Command" or any other types, we assume it's valid
    };

    ret
}


// ---------------------------------------------------------------
// Actions (now return Result so the TUI can show feedback)
// ---------------------------------------------------------------
pub fn action_add_rule(
    args: Vec<String>,
    tx: &mpsc::Sender<ControlMessage>
) -> Result <String, String>
{
    if args.len() < 2 {
        return Err("usage: add <IP> <Port>".into());
    }
    
    // IP 파싱 (예시: 192.168.4.131)
    // let ip_parts: Vec<u8> = args[0i]
        // .split('.')
        // .parse()
        // .map_err(|e| format!("bad ip '{}': not a valid IPv4 address", args[0]))?;
    let ip: std::net::Ipv4Addr = args[0]
        .parse()
        .map_err(|e| format!("bad ip '{}': {e}", args[0]))?;

    // let target_ip: [u8; 4] = [ip_parts[0], ip_parts[1], ip_parts[2], ip_parts[3]];
    let target_ip = ip.octets();
    
    // Port 파싱
    let target_port: u16 = args[1].parse().map_err(|e| format!("bad port '{}': {e}", args[1]))?;

    let msg = ControlMessage::AddRule { target_ip, target_port };
    tx.send(msg).map_err(|e| format!("Failed to send control message: {e}"))?;

    Ok("Rule addition command sent.".into())
}

pub fn action_remove_rule(
    args: Vec<String>,
    tx: &mpsc::Sender<ControlMessage>
) -> Result<String, String>
{
    if args.is_empty() { return Err("No arguments provided for remove rule.".into()); }

    let target_port: u16 = args[0]
        .parse()
        .map_err(|e| format!("bad port '{}': {e}", args[0]))?;

    let msg = ControlMessage::DeleteRule { target_port };
    tx.send(msg).map_err(|e| format!("Failed to send control message: {e}"))?;

    Ok("Rule removal command sent.".into())
}


pub fn execute_command(
    root: &CommandNode,
    input: &str,
    tx: &mpsc::Sender<ControlMessage>
) -> Result<String, String>
{
    let parts: Vec<&str> = input.trim().split_whitespace().collect();
    if parts.is_empty() {
        return Err("No command entered.".into());
    }

    let mut current = root;
    let mut args: Vec<String> = Vec::new();

    for part in parts {
        if let Some(child) = current.subcommands.get(part) {
            current = child;
        }
        else if let Some(child) = current.value_child.as_ref() {

            if !validate_command(part, child.arg_type) {
                return Err(format!("Invalid argument '{}' for type {:?}",
                    part, child.arg_type));
            }

            current = child;
            if child.arg_type != Some(ArgType::Command) {
                args.push(part.to_string());

            }
        }
        else {
            return  Err(format!("Command '{}' not found under '{}'", part, current.command));
        }
    }

    match current.action {
        Some(action) => {
           action(args, &tx);
           return Ok("Command executed successfully.".into());
        },
        None => return Err("incomplete command".into()),
    }
}



pub fn suggest_next_commands(command_tree: &CommandNode, input: &str)
    -> Vec<String>
{
    let parts: Vec<&str> = input.split_whitespace().collect();
    let current_node = find_node(command_tree, &parts);

	// let command = if input.is_empty() { "root" } else { input };
    // println!("Input parts: {:?}", parts);
    let mut suggestions: Vec<String> = Vec::new();
    let mut lines = Vec::new();

    match current_node {
        Some(node) => {
            if !node.subcommands.is_empty() {
                lines.push("next (keywords):".into());
                let mut keys: Vec<&String> = node.subcommands.keys().collect();
                keys.sort();
                for key in keys {
                    let sub = &node.subcommands[key];
                    lines.push(format!("  {}: {}", key, sub.description));
                }
            }

            if let Some(vc) = node.value_child.as_ref() {
                let kind = match vc.arg_type {
                    Some(ArgType::Ip) => "<IPv4 address>",
                    Some(ArgType::Port) => "<u16 port>",
                    _ => "<value>",
                };
                lines.push(format!("next (value): {} - {}", kind, vc.description));
            }

            if lines.is_empty() {
                if node.action.is_some() {
                    lines.push("This command can be executed.".into());
                } else {
                    lines.push("No further subcommands or values.".into());
                }
            }
        }
        None => {
            lines.push("No suggestions found.".into());
        }

    }

    lines
}


fn insert_in_depth<'a> (node: &'a mut CommandNode, command: &command::Command, depth: u32)
-> Option<&'a mut CommandNode>
{
	if &node.command == &command.parent && depth  == command.depth     {
        return Some(node);
	}

	if depth < command.depth {
		for child in node.subcommands.values_mut() {
            if let Some(found) = insert_in_depth(child, command, depth + 1) {
                return Some(found);
            }
        }
	}

    None
}

pub fn build_command_tree() -> CommandNode {
    let commands = command::make_commands();
    let mut root = CommandNode::new(
        "root",
        "Root command node",
        Some(ArgType::Command),
        None,
        None);

    for command in commands {
        root.insert(command);
    }

    root
}


pub fn cli_prompt(tx: mpsc::Sender<ControlMessage>)
    -> Result<(), String>
{
    // let stdout = io::stdout();
    let mut stdout = io::stdout().into_raw_mode().map_err(|e| format!("\n\rFailed to enable raw mode: {}", e))?;

    writeln!(stdout, "\n\rType commands. Press 'Tab' to see suggestions. Type 'exit' to quit.").map_err(|e| format!("\n\rFailed to write to stdout: {}", e))?;
    stdout.flush().unwrap();

    let command_tree = build_command_tree();

    // println!(" Command tree built: {:#?}", command_tree);
    let handle = thread::spawn(move || {
        // let stdin = Stdin();
        let mut input = String::new();

        print!("\r> "); // 사용자 프롬프트
        stdout.flush().unwrap();

        for evt in io::stdin().events() {
            // let evt: Event = evt.unwrap(); // 이벤트 처리 중 에러는 무시
            let evt: Event = match evt {
                Ok(e) => e,
                Err(_) => continue, // 에러 발생 시 무시하고 다음 이벤트로
            };

            match evt {

                Event::Key(Key::Char('\n')) => {
					if input.trim().is_empty() {
                        write!(stdout, "\n\r> ").unwrap();
					}
					else if input == "exit" || input == "quit" || input == "q"  {
                        writeln!(stdout, "\n\rExiting command interface.").unwrap();
						break;
					}
					else {
                		writeln!(stdout, "\n\rExecuting command: {}", input).unwrap();
                		execute_command(&command_tree, input.as_str(), &tx);
                		input.clear();
					}
                	write!(stdout, "\r> ").unwrap();
                }

                Event::Key(Key::Backspace) => {
                    input.pop();
                    write!(stdout, "\r> {}", input).unwrap();
                }

                Event::Key(Key::Char('\t')) => {
                    let trimmed_input = input.trim_end();
                    suggest_next_commands(&command_tree, trimmed_input);
                    write!(stdout, "\r> {} ", trimmed_input).unwrap();
                }

                Event::Key(Key::Char(c)) => {
                    input.push(c);
                    write!(stdout, "{}", c).unwrap();
                }

                //Input Ctrl+c or Esc key to cancel the command
				Event::Key(Key::Ctrl('c')) | Event::Key(Key::Esc) => {
                    input.clear();
                    write!(stdout, "\r> ").unwrap();
                }
                _ => {}
            }
            stdout.flush().unwrap();
        }
    });

    handle.join().map_err(|_| "Failed to join input thread.".to_string())?;

    Ok(())
}