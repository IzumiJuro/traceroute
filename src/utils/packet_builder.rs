// utils/packet_builder.rs
use std::net::Ipv4Addr;

use crate::utils::Protocol;
use pnet::{
    packet::{
        ethernet::{EtherTypes, MutableEthernetPacket},
        icmp::{IcmpCode, IcmpTypes, MutableIcmpPacket},
        ip::IpNextHeaderProtocols,
        ipv4::MutableIpv4Packet,
        tcp::{MutableTcpPacket, TcpFlags},
        udp::MutableUdpPacket,
        MutablePacket,
    },
    util::MacAddr,
};
use rand::Rng;

// 包构建器
pub struct PacketBuilder {
    pub protocol: Protocol, // 协议
    source_mac: MacAddr,    // 源MAC地址
    source_ip: Ipv4Addr,    // 源IP地址
}

// 实现PacketBuilder
impl PacketBuilder {
    // 创建一个包构建器
    pub fn new(protocol: Protocol, source_mac: MacAddr, source_ip: Ipv4Addr) -> Self {
        Self {
            protocol,
            source_mac,
            source_ip,
        }
    }

    // 构建一个包
    pub fn build_packet(&self, destination_ip: Ipv4Addr, ttl: u8, port: u16) -> Vec<u8> {
        match self.protocol {
            // 匹配协议
            Protocol::UDP => {
                Self::build_udp_packet(self.source_mac, self.source_ip, destination_ip, ttl, port)
                // 构建UDP包
            }
            Protocol::TCP => {
                Self::build_tcp_packet(self.source_mac, self.source_ip, destination_ip, ttl, port)
                // 构建TCP包
            }
            Protocol::ICMP => {
                Self::build_icmp_packet(self.source_mac, self.source_ip, destination_ip, ttl)
                // 构建ICMP包
            }
        }
    }

    // 构建一个UDP包
    fn build_udp_packet(
        source_mac: MacAddr,
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        ttl: u8,
        port: u16,
    ) -> Vec<u8> {
        let mut buf = [0u8; 66]; // 66字节的缓冲区
        let mut mut_ethernet_header = MutableEthernetPacket::new(&mut buf).unwrap(); // 以太网头部

        mut_ethernet_header.set_destination(MacAddr::zero()); // 目的MAC地址
        mut_ethernet_header.set_source(source_mac); // 源MAC地址
        mut_ethernet_header.set_ethertype(EtherTypes::Ipv4); // 以太网类型

        let mut ip_header = MutableIpv4Packet::new(mut_ethernet_header.payload_mut()).unwrap(); // IP头部

        ip_header.set_version(4); // IPv4
        ip_header.set_header_length(5); // 5个32位字
        ip_header.set_total_length(52); // 52bits的IP头部
        ip_header.set_ttl(ttl); // 生存时间
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp); // 下一层协议
        ip_header.set_source(source_ip); // 源IP地址
        ip_header.set_destination(destination_ip); // 目标IP地址
        ip_header.set_checksum(pnet::packet::ipv4::checksum(&ip_header.to_immutable())); // 计算校验和

        let mut udp_header = MutableUdpPacket::new(ip_header.payload_mut()).unwrap(); // UDP头部

        udp_header.set_source(rand::thread_rng().gen_range(1024..65535)); // 源端口
        udp_header.set_destination(port); // 目标端口
        udp_header.set_length(32); // 32字节的UDP头部
        udp_header.set_payload(&[0u8; 24]); // 24字节的负载
        udp_header.set_checksum(pnet::packet::udp::ipv4_checksum(
            &udp_header.to_immutable(),
            &source_ip,
            &destination_ip,
        )); // 计算校验和

        buf.to_vec() // 返回数据包
    }

    fn build_tcp_packet(
        source_mac: MacAddr,
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        ttl: u8,
        port: u16,
    ) -> Vec<u8> {
        let mut buf = [0u8; 78]; // 以太网头部 + IP头部 + TCP头部 + 负载
        let mut mut_ethernet_header = MutableEthernetPacket::new(&mut buf).unwrap(); // 以太网头部

        mut_ethernet_header.set_destination(MacAddr::zero()); // 目标MAC地址
        mut_ethernet_header.set_source(source_mac); // 源MAC地址
        mut_ethernet_header.set_ethertype(EtherTypes::Ipv4); // 以太网类型

        let mut ip_header = MutableIpv4Packet::new(mut_ethernet_header.payload_mut()).unwrap(); // IP头部

        ip_header.set_version(4); // IPv4
        ip_header.set_header_length(5); // 5个32位字
        ip_header.set_total_length(64); // 64字节的IP头部
        ip_header.set_ttl(ttl); // 生存时间
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp); // 下一层协议
        ip_header.set_source(source_ip); // 源IP地址
        ip_header.set_destination(destination_ip); // 目标IP地址
        ip_header.set_checksum(pnet::packet::ipv4::checksum(&ip_header.to_immutable())); // 计算校验和

        let mut tcp_header = MutableTcpPacket::new(ip_header.payload_mut()).unwrap(); // TCP头部

        tcp_header.set_source(rand::thread_rng().gen_range(1024..65535)); // 源端口
        tcp_header.set_destination(port); // 目标端口
        tcp_header.set_sequence(0); // 序列号
        tcp_header.set_data_offset(5); // 5个32位字
        tcp_header.set_acknowledgement(0); // 确认号
        tcp_header.set_flags(TcpFlags::SYN); // SYN标志
        tcp_header.set_window(0); // 窗口大小
        tcp_header.set_payload(&[0u8; 24]); // 24字节的负载
        tcp_header.set_checksum(pnet::packet::tcp::ipv4_checksum(
            &tcp_header.to_immutable(),
            &source_ip,
            &destination_ip,
        )); // 计算校验和

        buf.to_vec() // 返回数据包
    }

    fn build_icmp_packet(
        source_mac: MacAddr,
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        ttl: u8,
    ) -> Vec<u8> {
        let mut buf = [0u8; 86]; // 以太网头部 + IP头部 + ICMP头部 + 负载
        let mut mut_ethernet_header = MutableEthernetPacket::new(&mut buf).unwrap(); // 以太网头部

        mut_ethernet_header.set_destination(MacAddr::zero()); // 目标MAC地址
        mut_ethernet_header.set_source(source_mac); // 源MAC地址
        mut_ethernet_header.set_ethertype(EtherTypes::Ipv4); // 以太网类型

        let mut ip_header = MutableIpv4Packet::new(mut_ethernet_header.payload_mut()).unwrap(); // IP头部

        ip_header.set_version(4); // IPv4
        ip_header.set_header_length(5); // 5个32位字
        ip_header.set_total_length(72); // 72字节的IP头部
        ip_header.set_ttl(ttl); // 生存时间
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp); // 下一层协议
        ip_header.set_source(source_ip); // 源IP地址
        ip_header.set_destination(destination_ip); // 目标IP地址
        ip_header.set_checksum(pnet::packet::ipv4::checksum(&ip_header.to_immutable())); // 计算校验和

        let mut icmp_header = MutableIcmpPacket::new(ip_header.payload_mut()).unwrap(); // ICMP头部

        icmp_header.set_icmp_type(IcmpTypes::EchoRequest); // ICMP类型
        icmp_header.set_icmp_code(IcmpCode::new(0)); // ICMP代码
        icmp_header.set_payload(&[0u8; 32]); // 32字节的负载
        icmp_header.set_checksum(pnet::packet::icmp::checksum(&icmp_header.to_immutable())); // 计算校验和

        buf.to_vec() // 返回数据包
    }
}
