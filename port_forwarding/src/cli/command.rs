use std::sync::mpsc;
use crate::ControlMessage;
use crate::cli::commands_node::{action_add_rule, action_remove_rule};

type ActionFn = fn(Vec<String>, &mpsc::Sender<ControlMessage>);

#[derive(Debug, Clone)]
pub struct Command {
    pub command:        String,
    pub parent:         String,
    pub depth:          u32,
    pub description:    String,
    pub arg_type:       String,
    pub action:         Option<ActionFn>,
}


impl Command {

    pub fn new(
        command: &str,
        parent: &str,
        depth: u32,
        description: &str,
        arg_type: &str,
        action: Option<ActionFn>
    ) -> Self
    {
        Self {
            command:        command.to_string(),
            parent:         parent.to_string(),
            depth,
            description:    description.to_string(),
            arg_type:       arg_type.to_string(),
            action,
        }
    }
}


// root                           
//  │     
//  ├── add                       [Depth : 0] //Newly Added Command
//  │    └── "IP"                 [Depth : 1] // value argument
//  │          └── "port"         [Depth : 2] // value argument
//  └ quit/exit/q   
//  

pub fn make_commands() -> Vec<Command> {

    let mut commands = Vec::new();

    // Create the hierarchical structure of commands
    commands.push(Command::new("add",   "root", 0,  "Add a Rule",        "Command",  None));
    commands.push(Command::new("ip",    "add",  1,  "Target IP Address",    "IP",       None));
    commands.push(Command::new("port",  "ip",   2,  "Target Port",          "Port",     Some(action_add_rule)));

    commands.push(Command::new("remove",    "root",     0,  "Remove a Rule",        "Command",  None));
    commands.push(Command::new("port",      "remove",   1,  "Target Port",          "Port",     Some(action_remove_rule)));

    commands
}