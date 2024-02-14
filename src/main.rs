use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use clap::Parser;
use tracert::Traceroute;

use crate::{tracert::Config, utils::Protocol};

pub mod tracert;
pub mod utils;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value_t = 33433)]
    port: u16, // 端口
    #[arg(long, default_value_t = String::from("UDP"))]
    protocol: String, // 协议
    #[arg(short, long)]
    ip_or_domain: String,
    #[arg(short, long, default_value_t = 1)]
    timeout: u64, // 超时时间
    #[arg(short, long, default_value_t = 30)]
    max_hops: u32, // 最大跳数
    #[arg(short, long, default_value_t = 3)]
    number_of_queries: u32, // 每个跳数的查询次数
    #[arg(short, long, default_value_t = 1)]
    first_ttl: u8, // ttl
}

fn main() {
    let args = Args::parse();

    let destination_ip = if let Ok(ip) = Ipv4Addr::from_str(&args.ip_or_domain) {
        ip
    } else {
        let addrs = dns_lookup::lookup_host(&args.ip_or_domain).unwrap();
        println!("域名{}的IP地址为{}", &args.ip_or_domain, addrs[0]);
        // 将IP地址转换为Ipv4Addr
        addrs
            .iter()
            .find_map(|addr| match addr {
                IpAddr::V4(ip) => Some(*ip),
                _ => None,
            })
            .unwrap()
    };

    let protocol = match args.protocol.to_uppercase().as_str() {
        "UDP" => Protocol::UDP,
        "TCP" => Protocol::TCP,
        "ICMP" => Protocol::ICMP,
        _ => Protocol::UDP,
    };

    let traceroute_query = Traceroute::new(
        destination_ip,
        Config::default()
            .with_port(args.port)
            .with_protocol(protocol)
            .with_timeout(args.timeout)
            .with_max_hops(args.max_hops)
            .with_number_of_queries(args.number_of_queries)
            .with_first_ttl(args.first_ttl),
    ); // 创建Traceroute对象

    println!("ttl \trtt \t\taddr"); // 打印表头

    // 遍历traceroute_query
    for hop in traceroute_query {
        print!("{}", hop.ttl);
        // 如果hop.query_result为空，则说明已经到达目的地
        for query_result in &hop.query_result {
            println!(
                " \t{}ms \t\t{}",
                query_result.rtt.as_millis(),
                query_result.addr
            )
        }
    }
}
