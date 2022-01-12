use clap::{App, Arg};
use tcpip38::dns;
use url::Url;

fn main() -> () {
    let app = App::new("mget")
        .about("Full scratch HTTP GET")
        .arg(Arg::new("url").required(true))
        .arg(Arg::new("dns-server").default_value("8.8.8.8"))
        .get_matches();

    let dns_host = app.value_of("dns-server").unwrap();
    let dns_server = format!("{}:{}", dns_host, 53);
    println!("dns:  {}", dns_server);

    let url_str = app.value_of("url").unwrap();
    let url = Url::parse(url_str)
        .expect("error: unable to parse <url> as a URL");

    if url.scheme() != "http" {
        unimplemented!()
    }

    let ip_list = dns::resolve(
        url.host_str().unwrap(),
        dns_server.as_str(),
    );

    for ip in ip_list {
        println!("ip:  {:?}", ip);
        break;
    }
}
