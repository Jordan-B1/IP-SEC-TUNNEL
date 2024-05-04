use std::env;

mod keys_generator;
mod protocol;
mod cypher;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() == 2 {
        protocol::server::start_server(
            String::from("127.0.0.1"),
            args[1].parse().expect("Invalid argument"),
        )?;
    } else {
        protocol::client::start_client(
            args[1].clone(),
            args[2].parse().expect("Invalid argument: port"),
        )?;
    }
    Ok(())
}