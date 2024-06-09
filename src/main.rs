use std::env;

mod cypher;
mod keys_generator;
mod protocol;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() == 2 {
        protocol::server::run::start_server(
            String::from("127.0.0.1"),
            args[1].parse().expect("Invalid argument"),
        )?;
    } else {
        protocol::client::run::start_client(
            args[1].clone(),
            args[2].parse().expect("Invalid argument: port"),
        )?;
    }
    Ok(())
}
