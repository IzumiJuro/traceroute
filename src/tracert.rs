use std::{net::Ipv4Addr, time::Duration};

use pnet_datalink::NetworkInterface;

use crate::utils;
// 配置
pub struct Config {
    port: u16,               // 端口
    max_hops: u32,           // 最大跳数
    number_of_queries: u32,  // 每个跳数的查询次数
    ttl: u8,                 // ttl
    timeout: Duration,       // 超时时间
    channel: utils::Channel, // 通道
}
// Traceroute对象
pub struct Traceroute {
    addr: Ipv4Addr, // 目标地址
    config: Config, // 配置
    done: bool,     // 是否完成
}

// TracerouteHop对象
pub struct TracerouteHop {
    pub ttl: u8,                                  // ttl
    pub query_result: Vec<TracerouteQueryResult>, // 查询结果
}

// TracerouteQueryResult对象
pub struct TracerouteQueryResult {
    pub rtt: Duration, // 路由时间
    pub addr: String,  // 地址
}

// 实现Config的默认方法
impl Default for Config {
    fn default() -> Self {
        Config {
            port: 33434,                     // 端口
            max_hops: 30,                    // 最大跳数
            number_of_queries: 3,            // 每个跳数的查询次数
            ttl: 1,                          // ttl
            timeout: Duration::from_secs(1), // 超时时间
            channel: Default::default(),     // 通道
        }
    }
}

// 实现Config的方法
impl Config {
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port; // 设置端口
        self
    }
    pub fn with_max_hops(mut self, max_hops: u32) -> Self {
        self.max_hops = max_hops; // 设置最大跳数
        self
    }

    pub fn with_number_of_queries(mut self, number_of_queries: u32) -> Self {
        self.number_of_queries = number_of_queries; // 设置每个跳数的查询次数
        self
    }

    pub fn with_protocol(mut self, protocol: utils::Protocol) -> Self {
        self.channel.change_protocol(protocol); // 设置通道的协议
        self
    }

    pub fn with_interface(mut self, interface: NetworkInterface) -> Self {
        self.channel = utils::Channel::new(interface, self.port, self.ttl); // 设置通道
        self
    }

    pub fn with_first_ttl(mut self, first_ttl: u8) -> Self {
        self.ttl = first_ttl; // 设置ttl
        self
    }

    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = Duration::from_millis(timeout); // 设置超时时间
        self
    }
}

// 实现Traceroute的方法
impl Traceroute {
    // 创建Traceroute对象
    pub fn new(addr: Ipv4Addr, config: Config) -> Self {
        Traceroute {
            addr,
            config,
            done: false,
        }
    }

    // 执行traceroute
    pub fn perform_traceroute(&mut self) -> Vec<TracerouteHop> {
        let mut hops = Vec::with_capacity(self.config.max_hops as usize); // 创建一个容量为max_hops的Vec
        for _ in 1..self.config.max_hops {
            // 遍历max_hops
            if self.done {
                // 如果完成
                return hops; // 返回hops
            }
            if let Some(hop) = self.next() {
                // 如果有下一个hop
                hops.push(hop); // 将hop添加到hops中
            }
        }
        hops // 返回hops
    }

    // 获取下一个查询结果
    fn get_next_query_result(&mut self) -> TracerouteQueryResult {
        let now = std::time::Instant::now(); // 获取当前时间

        self.config.channel.send_to(self.addr); // 发送数据包到目标地址
        let hop_ip = self
            .config
            .channel
            .recv_timeout(Duration::from_millis(1000)); // 接收数据包
        TracerouteQueryResult {
            rtt: now.elapsed(), // 计算路由时间
            addr: hop_ip,       // 获取地址
        }
    }

    // 计算下一个跳数
    pub fn calculate_next_hop(&mut self) -> TracerouteHop {
        let mut query_results = Vec::<TracerouteQueryResult>::new(); // 创建一个空的Vec
        for _ in 0..self.config.number_of_queries {
            // 遍历number_of_queries
            let result = self.get_next_query_result(); // 获取下一个查询结果
            if result.addr == "*"
                || !query_results
                    .iter()
                    .any(|query_result| query_result.addr == result.addr)
            // 如果地址不是*并且query_results中没有相同的地址
            {
                query_results.push(result) // 将result添加到query_results中
            }
        }
        TracerouteHop {
            ttl: self.config.channel.increment_ttl(), // 增加ttl
            query_result: query_results,              // 设置查询结果
        }
    }
}

// 实现对TraceRoute的迭代
impl Iterator for Traceroute {
    type Item = TracerouteHop;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            // 如果完成
            return None; // 返回None
        }
        let hop = self.calculate_next_hop(); // 计算下一个跳数
        if hop
            .query_result
            .iter()
            .any(|query_result| query_result.addr == self.addr.to_string())
        // 如果hop的query_result中有目标地址
        {
            self.done = true; // 设置完成
        }
        Some(hop) // 返回hop
    }
}
