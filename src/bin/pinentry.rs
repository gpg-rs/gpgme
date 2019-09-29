use std::{io, io::prelude::*};

#[allow(dead_code)]
fn main() {
    println!("OK Your orders please");

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    while let Some(Ok(cmd)) = lines.next() {
        match cmd.split(' ').nth(0) {
            Some("GETPIN") => {
                println!("D abc");
                println!("OK");
            }
            _ => println!("OK"),
        }
    }
}
