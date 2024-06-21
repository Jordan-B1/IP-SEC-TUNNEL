use std::env;

mod cypher;
mod keys_generator;
mod protocol;

/// Starting point of the program
///
/// It will run different code depending on the number of arguments
/// If given 2 arguments (ip address and port), it will start a client
/// If given 1 argument (port), it will start a server
fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() == 2 {
        protocol::server::run::start_server(
            String::from("127.0.0.1"),
            args[1].parse().expect("Invalid argument"),
        );
    } else {
        protocol::client::run::start_client(
            args[1].clone(),
            args[2].parse().expect("Invalid argument: port"),
        );
    }
    Ok(())
}
