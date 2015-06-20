use std::io;
use std::io::prelude::*;

#[allow(dead_code)]
fn main() {
    let stdin = io::stdin();
    println!("OK Your orders please");
    for cmd in stdin.lock().lines() {
        match cmd.unwrap().as_ref() {
            "GETPIN" => {
                println!("D abc");
                println!("OK");
            },
            _ => println!("OK"),
        }
    }
}
