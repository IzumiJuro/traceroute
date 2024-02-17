// utils/mod.rs
extern crate pnet;
mod packet_builder;
use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    time::Duration,
};

use async_std::task::block_on;
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    icmp::{IcmpPacket, IcmpTypes},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    Packet,
};
use pnet_datalink::{channel, MacAddr, NetworkInterface};

#[derive(PartialEq)]
// 枚举协议
pub enum Protocol {
    UDP,
    TCP,
    ICMP,
}

pub struct Channel {
    // 通道
    interface: NetworkInterface,                   // 网络接口
    packet_builder: packet_builder::PacketBuilder, // 数据包构建器
    payload_offset: usize,                         // 负载偏移量
    port: u16,                                     // 端口
    ttl: u8,                                       // TTL
    seq: u16,                                      // 序列号
}

// 实现Channel的默认值
impl Default for Channel {
    fn default() -> Self {
        let available_interfaces = get_available_interfaces(); // 获取可用的网络接口

        let default_interface = available_interfaces
            .iter()
            .next()
            .expect("no interfaces available")
            .clone(); // 默认网络接口

        Channel::new(default_interface, 33434, 1) // 默认通道
    }
}

// 实现Channel的方法
impl Channel {
    // 创建一个通道
    pub fn new(network_interface: NetworkInterface, port: u16, ttl: u8) -> Self {
        let source_ip = network_interface
            .ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .expect("couldn't get interface IP")
            .ip()
            .to_string(); // 源IP地址

        let source_ip = Ipv4Addr::from_str(source_ip.as_str()).expect("couldn't parse IP"); // 源IP地址
        let payload_offset = if cfg!(any(target_os = "macos", target_os = "ios"))
            && network_interface.is_up()
            && !network_interface.is_broadcast()
            && ((!network_interface.is_loopback() && network_interface.is_point_to_point())
                || network_interface.is_loopback())
        {
            if network_interface.is_loopback() {
                14
            } else {
                0
            }
        } else {
            0
        }; // 负载偏移量

        Channel {
            interface: network_interface.clone(), // 网络接口
            packet_builder: packet_builder::PacketBuilder::new(
                Protocol::UDP,
                network_interface.mac.expect("couldn't get interface MAC"),
                source_ip,
            ), // 数据包构建器
            payload_offset,                       // 负载偏移量
            port,                                 // 端口
            ttl,                                  // TTL
            seq: 0,                               // 序列号
        } // 通道
    }

    pub fn change_protocol(&mut self, new_protocol: Protocol) {
        self.packet_builder.protocol = new_protocol; // 更改协议
    }

    pub fn increment_ttl(&mut self) -> u8 {
        self.ttl += 1; // TTL加1
        self.ttl - 1
    }

    pub fn max_hops_reached(&self, max_hops: u8) -> bool {
        self.ttl > max_hops // TTL大于最大跳数
    }

    // 发送数据包
    pub fn send_to(&mut self, destination_ip: Ipv4Addr) {
        let (mut tx, _) = match channel(&self.interface, Default::default()) {
            Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx), // 以太网通道
            Ok(_) => panic!("unhandled channel type"),                // 未处理的通道类型
            Err(e) => panic!("error while creating channel: {e}"),    // 创建通道时出错
        };
        let buf = self
            .packet_builder
            .build_packet(destination_ip, self.ttl, self.port + self.seq); // 构建数据包
        tx.send_to(&buf, None); // 发送数据包
        if self.packet_builder.protocol != Protocol::TCP {
            self.seq += 1; // 序列号加1
        }
    }

    // 接收数据包
    async fn recv(interface: NetworkInterface, payload_offset: usize) -> String {
        loop {
            if let Ok(ip) = process_incoming_packet(interface.clone(), payload_offset) {
                return ip; // 返回IP地址
            }
        }
    }

    // 接收数据包并处理超时
    pub fn recv_timeout(&mut self, timeout: Duration) -> String {
        let processor =
            async_std::task::spawn(Self::recv(self.interface.clone(), self.payload_offset));
        block_on(async {
            match async_std::future::timeout(timeout, processor).await {
                Ok(ip) => ip,
                Err(_) => String::from("请求超时"),
            }
        })
    }
}

// 获取可用的网络接口
pub fn get_available_interfaces() -> Vec<NetworkInterface> {
    let all_interfaces = pnet_datalink::interfaces(); // 所有网络接口

    available_interfaces = if cfg!(target_family = "windows") {
        all_interfaces
            .into_iter()
            .filter(|e| {
                e.mac.is_some()
                    && e.mac.unwrap() != MacAddr::zero()
                    && e.ips
                        .iter()
                        .filter(|ip| ip.ip().to_string() != "0.0.0.0")
                        .next()
                        .is_some()
            })
            .collect()
    } else {
        all_interfaces
            .into_iter()
            .filter(|e| {
                e.is_up()
                    && !e.is_loopback()
                    && e.ips.iter().filter(|ip| ip.is_ipv4()).next().is_some()
                    && e.mac.is_some()
                    && e.mac.unwrap() != MacAddr::zero()
            })
            .collect()
    }; // 过滤出可用的网络接口

    available_interfaces // 返回可用的网络接口
}

// 处理ICMP数据包
fn handle_icmp_packet(source: IpAddr, packet: &[u8]) -> Result<String, &'static str> {
    let icmp_packet = IcmpPacket::new(packet).expect("couldn't parse ICMP packet"); // ICMP数据包

    match icmp_packet.get_icmp_type() {
        // ICMP类型
        IcmpTypes::EchoReply => Ok(source.to_string()), // 回显应答
        IcmpTypes::TimeExceeded => Ok(source.to_string()), // 超时
        IcmpTypes::DestinationUnreachable => Ok(source.to_string()), // 目的地不可达
        _ => Err("unknown ICMP type"),                  // 未知的ICMP类型
    }
}

// 处理IPv4数据包
fn handle_ipv4_packet(packet: &[u8]) -> Result<String, &'static str> {
    let header = Ipv4Packet::new(packet).expect("couldn't parse IPv4 packet"); // IPv4数据包

    let source = IpAddr::V4(header.get_source()); // 源IP地址
    let payload = header.payload(); // 负载

    match header.get_next_level_protocol() {
        // 下一层协议
        IpNextHeaderProtocols::Icmp => handle_icmp_packet(source, payload), // ICMP
        _ => Err("unknown IP protocol"),                                    // 未知的IP协议
    }
}

// 处理以太网数据包
fn handle_ethernet_frame(packet: &[u8]) -> Result<String, &'static str> {
    let ethernet = EthernetPacket::new(packet).expect("couldn't parse Ethernet packet"); // 以太网数据包
    match ethernet.get_ethertype() {
        // 以太网类型
        EtherTypes::Ipv4 => handle_ipv4_packet(ethernet.payload()), // IPv4
        _ => Err("unknown Ethernet type"),                          // 未知的以太网类型
    }
}

// 处理传入的数据包
fn process_incoming_packet(
    interface: NetworkInterface,
    payload_offset: usize,
) -> Result<String, &'static str> {
    let (_, mut rx) = match channel(&interface, Default::default()) {
        // 通道
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx), // 以太网
        Ok(_) => panic!("unhandled channel type"),                // 未处理的通道类型
        Err(e) => panic!("error while creating channel: {e}"),    // 创建通道时出错
    };

    match rx.next() {
        // 下一个数据包
        Ok(packet) => {
            if payload_offset > 0 && packet.len() > payload_offset {
                // 负载偏移量大于0且数据包长度大于负载偏移量
                return handle_ipv4_packet(&packet[payload_offset..]); // 处理IPv4数据包
            }
            handle_ethernet_frame(packet) // 处理以太网数据包
        }
        Err(e) => panic!("error while reading: {e}"), // 读取数据包时出错
    }
}
