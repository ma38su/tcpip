use anyhow::Result;
use clap::{App, Arg};
use std::net::Ipv4Addr;

use tcpip38::tcp::TCP;

fn main() -> Result<()> {
    let app = App::new("echoserver")
        .about("Full scratch Echo Server")
        .arg(Arg::new("ip").required(true))
        .arg(Arg::new("port").required(true))
        .get_matches();

    let ip_str = app.value_of("ip").unwrap();
    let port = app.value_of("port").unwrap().parse().unwrap();
    println!("server:  {}:{}", ip_str, port);

    let ip = ip_str.parse()?;
    echo_server(ip, port)?;
    Ok(())
}

fn echo_server(local_addr: Ipv4Addr, local_port: u16) -> Result<()> {
    let tcp = TCP::new();
    let listening_socket = tcp.listen(local_addr, local_port)?;
    dbg!("listening...", &local_addr, &local_port);
    loop {
        let connected_addrs = tcp.accept(listening_socket)?;
        dbg!("accepted!",
            connected_addrs.remote_addr(),
            connected_addrs.remote_port(),
        );
    }
}
