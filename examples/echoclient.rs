use std::net::Ipv4Addr;

use anyhow::Result;
use clap::{App, Arg};
use tcpip38::tcp::TCP;

fn main() -> Result<()> {
    let app = App::new("mget")
        .about("Full scratch HTTP GET")
        .arg(Arg::new("ip").required(true))
        .arg(Arg::new("port").required(true))
        .arg(Arg::new("dns-server").default_value("8.8.8.8"))
        .get_matches();

    let ip_str = app.value_of("ip").unwrap();
    let port = app.value_of("port").unwrap().parse().unwrap();
    println!("server:  {}:{}", ip_str, port);

    let dns_host = app.value_of("dns-server").unwrap();
    let dns_server = format!("{}:{}", dns_host, 53);
    println!("dns:  {}", dns_server);

    let ip = ip_str.parse()?;
    echo_client(ip, port).unwrap();

    Ok(())
}

fn echo_client(remote_addr: Ipv4Addr, remote_port: u16) -> Result<()> {
    let tcp = TCP::new();
    tcp.connect(remote_addr, remote_port)?;
    Ok(())
}
