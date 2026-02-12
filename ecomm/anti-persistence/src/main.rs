use std::io;
use crate::{cron::check_cron, php_shells::check_php_shells, systemd_services::check_services};

mod cron;
mod php_shells;
mod systemd_services;

fn main() {
    title();
    loop {
        menu();
        let mut menu_input: String = String::new();

        io::stdin()
            .read_line(&mut menu_input)
            .expect("Failed to read line");

        let menu_number: u8 = match menu_input.trim().parse() {
            Ok(num) => num,
            Err(_) => {
                println!("Invalid input.");
                return;
            }
        };

        match menu_number {
            1 => check_cron(),
            2 => check_services(),
            3 => check_php_shells(),
            4 => check_all(),
            99 => {
                println!("Exiting...");
                return;
            }
            _ => println!("Invalid selection")
        }
    }
}



fn title() {
    println!(r"  /============================================================\
  ||     ____                 _      __                       ||
  ||    / __ \___  __________(_)____/ /____  ____  ________   ||
  ||   / /_/ / _ \/ ___/ ___/ / ___/ __/ _ \/ __ \/ ___/ _ \  ||
  ||  / ____/  __/ /  (__  ) (__  ) /_/  __/ / / / /__/  __/  ||
  || /_/ ___\___/_/  /____/_/____/\__/\___/_/ /_/\___/\___/   ||
  ||    / __ \__  ___________ ____  _____                     ||
  ||   / /_/ / / / / ___/ __ \`/ _ \/ ___/                    ||
  ||  / ____/ /_/ / /  / /_/ /  __/ /                         ||
  || /_/    \__,_/_/   \__, /\___/_/                          ||
  ||                  /____/                                  ||
  \============================================================/");
}

fn menu() {
    println!("1 - Check for Cron Jobs");
    println!("2 - Check for Services");
    println!("3 - Check for PHP Shells");
    println!("4 - Check All");
    println!("99 - Exit");
}


fn check_all() {
    check_cron();
    check_services();
    check_php_shells();
}
