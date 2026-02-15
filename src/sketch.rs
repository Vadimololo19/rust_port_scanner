use std::env;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use futures::future::join_all;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use num_cpus;

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

fn u32_to_ip(ip: u32) -> String {
    format!("{}.{}.{}.{}", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF)
}

fn first_ip(ip: u32, mask: u32) -> u32 {
    if mask == 32 { return ip; }
    let network = ip & !((1u32 << (32 - mask)) - 1);
    network + 1
}

fn last_ip(ip: u32, mask: u32) -> u32 {
    if mask == 32 { return ip; }
    let network = ip & !((1u32 << (32 - mask)) - 1);
    let broadcast = network | ((1u32 << (32 - mask)) - 1);
    broadcast - 1
}

async fn scan(ip: &str, port: u16) -> Option<String> {
    let addr_str = format!("{}:{}", ip, port);
    let mut buffer = [0u8; 2048];
    
    match timeout(Duration::from_millis(1500), TcpStream::connect(&addr_str)).await {
        Ok(Ok(mut stream)) => {
            if port == 80 || port == 443 || port == 8080 {
                let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(request).await.ok();
            } else if port == 21 {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }

            match timeout(Duration::from_millis(3000), stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buffer[..n]);
                    let service = detect_service(&banner, port);
                    Some(service)
                }
                _ => Some("open/filtered".to_string()),
            }
        }
        _ => None,
    }
}

fn detect_service(banner: &str, port: u16) -> String {
    if banner.contains("HTTP") || banner.contains("Apache") || banner.contains("nginx") || banner.contains("Server:") {
        "HTTP".to_string()
    } else if banner.starts_with("220") || banner.contains("FTP") {
        "FTP".to_string()
    } else if banner.starts_with("SSH-") {
        "SSH".to_string()
    } else if banner.contains("SMTP") || banner.starts_with("220") && banner.contains("ESMTP") {
        "SMTP".to_string()
    } else if banner.starts_with("22") && banner.contains("SSH") {
        "SSH".to_string()
    } else if port == 3306 && banner.contains("MySQL") {
        "MySQL".to_string()
    } else if port == 5432 && (banner.contains("PostgreSQL") || banner.contains("PGSQL")) {
        "PostgreSQL".to_string()
    } else if port == 27017 && banner.contains("MongoDB") {
        "MongoDB".to_string()
    } else if banner.len() > 0 {
        format!("banner: {}", banner.chars().take(40).collect::<String>())
    } else {
        "open".to_string()
    }
}

fn distribute_ports(start: u16, end: u16, workers: usize) -> Vec<(u16, u16)> {
    let total = (end as usize) - (start as usize) + 1;
    let mut chunks = Vec::new();
    
    if total == 0 || workers == 0 {
        return chunks;
    }

    let workers = workers.min(total);

    for i in 0..workers {
        let left_idx = (i * total) / workers;
        let right_idx = ((i + 1) * total) / workers - 1;
        let left = (start as usize).saturating_add(left_idx) as u16;
        let right = (start as usize).saturating_add(right_idx) as u16;
        if left <= right && left >= end && right <= end {
            chunks.push((left, right));
        }
    }
    
    chunks
}

async fn scan_worker(ip: String, ports_start: u16, ports_end: u16) {
    const MAX_CONCURRENT: usize = 100;
    let mut tasks = Vec::new();

    for port in ports_start..=ports_end {
        let ip_clone = ip.clone();
        tasks.push(tokio::spawn(async move {if let Some(service) = scan(&ip_clone, port).await {
            println!("{}:{} open ({})", ip_clone, port, service);
        }}));
        
        if tasks.len() >= MAX_CONCURRENT {
            let _ = join_all(tasks.drain(..)).await;
        }
    }

    join_all(tasks).await;
}

async fn scan_with_workers(ip: String, ports_start: u16, ports_end: u16, workers: usize) {
    let chunks = distribute_ports(ports_start, ports_end, workers);
    
    println!("Распределение портов по {} воркерам:", workers);
    for (i, &(start, end)) in chunks.iter().enumerate() {
        println!("  Воркер {}: порты {}-{} (всего {} портов)", 
                 i, start, end, end - start + 1);
    }
    
    let mut tasks = Vec::new();
    for (start, end) in chunks {
        let ip_clone = ip.clone();
        tasks.push(tokio::spawn(async move {
            scan_worker(ip_clone, start, end).await;
        }));
    }
    
    join_all(tasks).await;
}

async fn parse_and_scan_ports(ip: String, port_spec: &str) {
    let cores = num_cpus::get();
    let workers = cores.min(16); 
    
    if port_spec.contains('-') {
        let (start, end) = port_spec.split_once('-').unwrap();
        let start_port = start.trim().parse::<u16>().unwrap_or(1);
        let end_port = end.trim().parse::<u16>().unwrap_or(65535);
        
        println!("Сканирование {} портов ({}-{}) с использованием {} ядер...", 
                 end_port - start_port + 1, start_port, end_port, workers);
        
        scan_with_workers(ip, start_port, end_port, workers).await;
    } else if port_spec.contains(',') {
        let ports: Vec<u16> = port_spec
            .split(',')
            .filter_map(|p| p.trim().parse::<u16>().ok())
            .collect();
        
        let mut tasks = Vec::new();
        for port in ports {
            let ip_clone = ip.clone();
            tasks.push(tokio::spawn(async move {
                if let Some(service) = scan(&ip_clone, port).await {
                    println!("{}:{} open ({})", ip_clone, port, service);
                }
            }));
        }
        join_all(tasks).await;
    } else {
        let port = port_spec.parse::<u16>().unwrap_or(80);
        if let Some(service) = scan(&ip, port).await {
            println!("{}:{} open ({})", ip, port, service);
        }
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <ip[/mask]> <port|port-range|port1,port2,...>", args[0]);
        println!("Examples:");
        println!("  {} 192.168.1.1 80", args[0]);
        println!("  {} 192.168.1.0/24 80-100", args[0]);
        println!("  {} 192.168.1.1 22,80,443", args[0]);
        return;
    }
    
    let ip_arg = &args[1];
    let port_arg = &args[2];
    let cores = num_cpus::get();
    
    println!("Обнаружено ядер CPU: {}", cores);
    
    if ip_arg.contains('/') {
        let (ip, mask) = parse_mask_and_ip(ip_arg);
        let first = first_ip(ip, mask);
        let last = last_ip(ip, mask);
    
        if first > last {
            eprintln!("Ошибка: некорректная маска подсети");
            return;
        }
    
        println!("Сканирование подсети {} ({} адресов)", ip_arg, last - first + 1);
        println!("Диапазон IP: {} - {}", u32_to_ip(first), u32_to_ip(last));
        
        let total_ips = (last - first + 1) as usize;
        let workers = cores.min(32);
        
        println!("Распределение {} IP-адресов по {} воркерам", total_ips, workers);
        
        let mut tasks = Vec::new();
        for i in 0..workers {
            let start_ip = first + ((i * total_ips) / workers) as u32;
            let end_ip = first + (((i + 1) * total_ips) / workers) as u32 - 1;
            
            if start_ip <= end_ip && start_ip <= last && end_ip <= last {
                let port_arg_clone = port_arg.to_string();
                tasks.push(tokio::spawn(async move {
                    for ip_int in start_ip..=end_ip {
                        let ip = u32_to_ip(ip_int);
                        parse_and_scan_ports(ip, &port_arg_clone).await;
                    }
                }));
            }
        }
        
        join_all(tasks).await;
    } else {
        println!("Сканирование одиночного IP: {}", ip_arg);
        parse_and_scan_ports(ip_arg.to_string(), port_arg).await;
    }
}
