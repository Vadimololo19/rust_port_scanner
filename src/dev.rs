use std::env;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use futures::future::join_all;
use tokio::io::{AsyncReadExt,AsyncWriteExt};

fn parse_mask_and_ip(host_name: &str) -> (u32, u32) {
    let parts: Vec<&str> = host_name.split('/').collect();
    let ip_str = parts[0];
    let mask = parts[1].parse::<u32>().unwrap();
    
    let ip_parts: Vec<u32> = ip_str.split('.')
        .map(|s| s.parse().unwrap())
        .collect();
    let ip = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3];
    
    (ip, mask)
}

fn parse_IP_to_int(ip: &str) -> u32 {
    let ip_list: Vec<u32> = ip.split('.').map(|x| x.parse().unwrap()).collect();
    let mut ip_int = 0;
    for i in 0..4 {
        ip_int += ip_list[i] << (24 - 8 * i);
    }
    ip_int
}

fn first_IP(ip: u32, mask: u32) -> u32 {
    if mask == 32 { return ip;}
    let network = ip & !((1u32 << (32 - mask)) - 1);
    network + 1
}

fn last_IP(ip: u32, mask: u32) -> u32 {
    if mask == 32 { return ip;}
    let network = ip & !((1u32 << (32 - mask)) - 1);
    let broadcast = network | ((1u32 << (32 - mask)) - 1);
    broadcast - 1
}

fn parse_int_to_IP(ip_int: u32) -> String {
    let mut part_ip = Vec::new();
    for i in (0..4).rev() {
        part_ip.push((ip_int >> (8 * i) & 0xFF).to_string());
    }
    part_ip.join(".")
}

fn u32_to_ip(ip: u32) -> String {
    format!("{}.{}.{}.{}", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF)
}

async fn scan(ip: &str, port: &str) {
    let addr_str = format!("{}:{}", ip, port);
    let mut buffer = [0u8; 2048];
    match timeout(Duration::from_millis(1500), TcpStream::connect(&addr_str)).await {
        Ok(Ok(mut stream)) => {
            if port == "80" || port == "443" { 
                let request = b"GET / HTTP/1.1\r\nHost: howdy?\r\n\r\n";
                let _ = stream.write_all(request).await;
            }

            match timeout(Duration::from_millis(3000), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => { 
                let banner = String::from_utf8_lossy(&buffer[..n]);
                let service = if banner.contains("HTTP") || banner.contains("Apache") { "HTTP".to_string() } else if banner.starts_with("220") { "FTP".to_string() } 
                else if banner.starts_with("SSH-") { "SSH".to_string() } else { banner.chars().take(50).collect::<String>() };

            println!("{}: {} open, service {}", ip, port, service);
                //String::from_utf8_lossy(&buffer).trim());
                }
                _ => {println!("{}: {} open/filtered", ip, port);}
            }
        }
        //_ => {println!("{}: {} timeout", ip, port);}
    }
}

async fn scan_cycle(ip: String, port: String) {
    if port.contains('-') {
        let (start, end) = port.split_once('-').unwrap();
        let start = start.trim().parse::<u16>().unwrap();
        let end = end.trim().parse::<u16>().unwrap();
        
        let mut tasks = vec![];
        for p in start..=end {
            let ip_owned = ip.clone();
            tasks.push(tokio::spawn(async move {
                scan(&ip_owned, &p.to_string()).await;
            }));
        }
        join_all(tasks).await;
    } else if port.contains(',') {
        let ports = port.split(',');
        let mut tasks = vec![];
        for p in ports {
            let ip_owned = ip.clone();
            let port_owned = p.trim().to_string();
            tasks.push(tokio::spawn(async move {
                scan(&ip_owned, &port_owned).await;
            }));
        }
        join_all(tasks).await;
    } else {
        scan(&ip, &port).await;
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <ip[/mask]> <port|port-range>", args[0]);
        return;
    }
    
    let ip_arg = &args[1];
    let mut ip_owned = ip_arg.to_string();
    let port_arg = args[2].clone();
    if ip_arg.contains('/') {
        let (ip, mask) = parse_mask_and_ip(ip_arg);
        let first = first_IP(ip, mask);
        let last = last_IP(ip, mask);
    
        if first > last {
            return;
        }
    
        println!("Scanning from {} to {}", u32_to_ip(first), u32_to_ip(last));
    
        let mut tasks = vec![];
        for i in first..=last {
            let current_ip = u32_to_ip(i);
            let value = port_arg.clone();
            tasks.push(tokio::spawn(async move {
                scan_cycle(current_ip, value).await;
            }));
        }
        join_all(tasks).await;
    } else {
        println!("Scanning single IP: {}", ip_arg);
        scan_cycle(ip_owned, port_arg).await;
    }

    //let(ip, mask) = parse_mask_and_ip(&args[1]);
    //let first = first_IP(ip, mask);
    //let last = last_IP(ip, mask);
    //let port_arg = args[2].clone();
    
    //println!("Scanning from {} to {}", u32_to_ip(first), u32_to_ip(last));
    //println!("Ports: {}", port_arg);

    //let mut tasks = vec![];
    //for i in first..=last {
    //    let current_ip = u32_to_ip(i);
    //    let port_owned = port_arg.clone();
    //    tasks.push(tokio::spawn(async move {
    //        scan_cycle(current_ip, port_owned).await;
    //    }));
    //}
    //join_all(tasks).await;

}

