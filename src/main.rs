use std::env;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use futures::future::join_all;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use num_cpus;
use std::time::Instant;

fn show_uptime() -> Duration {
    static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    
    let start_time = START_TIME.get_or_init(Instant::now);
    let uptime = start_time.elapsed();
    
    let total_secs = uptime.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    
    println!("Программа работает: {}ч {}мин {}сек", hours, minutes, seconds);
    
    Duration::from_secs(total_secs)
}

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

async fn scan(ip: &str, port: u16, semaphore: Arc<Semaphore>) -> Option<String> {
    let _permit = semaphore.acquire().await.ok()?;
    
    let addr_str = format!("{}:{}", ip, port);
    let mut buffer = [0u8; 2048];
    
    match timeout(Duration::from_millis(1500), TcpStream::connect(&addr_str)).await {
        Ok(Ok(mut stream)) => {
            if port == 80 || port == 443 || port == 8080 {
                let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(request).await.ok();
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            match timeout(Duration::from_millis(2000), stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buffer[..n]);
                    Some(detect_service(&banner, port))
                }
                _ => Some("open/filtered".to_string()),
            }
        }
        _ => None,
    }
}

fn detect_service(banner: &str, port: u16) -> String {
    if banner.contains("HTTP") || banner.contains("Apache") || banner.contains("nginx") {
        "HTTP".to_string()
    } else if banner.starts_with("220") || banner.contains("FTP") {
        "FTP".to_string()
    } else if banner.starts_with("SSH-") {
        "SSH".to_string()
    } else if banner.contains("MySQL") {
        "MySQL".to_string()
    } else if banner.contains("PostgreSQL") {
        "PostgreSQL".to_string()
    } else {
        "open".to_string()
    }
}

fn distribute_range(start: usize, end: usize, chunks: usize) -> Vec<(usize, usize)> {
    let total = end - start + 1;
    let chunks = chunks.min(total);
    (0..chunks)
        .map(|i| {
            let left = start + (i * total) / chunks;
            let right = start + ((i + 1) * total) / chunks - 1;
            (left, right)
        })
        .collect()
}

async fn scan_port_range(ip: String, ports_start: u16, ports_end: u16, semaphore: Arc<Semaphore>) {
    let total_ports = (ports_end - ports_start + 1) as usize;
    let mut tasks = Vec::new();
    
    for port in ports_start..=ports_end {
        let ip_clone = ip.clone();
        let sem_clone = semaphore.clone();
        tasks.push(tokio::spawn(async move {
            if let Some(service) = scan(&ip_clone, port, sem_clone).await {
                println!("{}:{} open ({})", ip_clone, port, service);
            }
        }));
    }
    
    let _ = join_all(tasks).await;
}

async fn scan_single_host(ip: String, port_spec: &str, max_concurrent: usize) {
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    
    if port_spec.contains('-') {
        let (start, end) = port_spec.split_once('-').unwrap();
        let start_port = start.trim().parse::<u16>().unwrap_or(1);
        let end_port = end.trim().parse::<u16>().unwrap_or(65535);
        
        if start_port > end_port {
            eprintln!("Ошибка: некорректный диапазон портов");
            return;
        }
        
        let total = end_port - start_port + 1;
        println!("Сканирование {} портов на {} (макс. {} соединений)...", total, ip, max_concurrent);
        scan_port_range(ip, start_port, end_port, semaphore).await;
    } else if port_spec.contains(',') {
        let ports: Vec<u16> = port_spec
            .split(',')
            .filter_map(|p| p.trim().parse::<u16>().ok())
            .collect();
        
        println!("Сканирование {} портов на {}...", ports.len(), ip);
        let mut tasks = Vec::new();
        
        for port in ports {
            let ip_clone = ip.clone();
            let sem_clone = semaphore.clone();
            tasks.push(tokio::spawn(async move {
                if let Some(service) = scan(&ip_clone, port, sem_clone).await {
                    println!("{}:{} open ({})", ip_clone, port, service);
                }
            }));
        }
        
        let _ = join_all(tasks).await;
    } else {
        let port = port_spec.parse::<u16>().unwrap_or(80);
        if let Some(service) = scan(&ip, port, semaphore).await {
            println!("{}:{} open ({})", ip, port, service);
        }
    }
}

async fn scan_network(cidr: &str, port_spec: &str, max_concurrent: usize) {
    let (ip, mask) = parse_mask_and_ip(cidr);
    let first = first_ip(ip, mask);
    let last = last_ip(ip, mask);
    
    if first > last {
        eprintln!("Ошибка: некорректная маска подсети");
        return;
    }
    
    let total_ips = (last - first + 1) as usize;
    println!("Сканирование подсети {} ({} хостов), порты: {}", cidr, total_ips, port_spec);
    println!("Диапазон IP: {} - {}", u32_to_ip(first), u32_to_ip(last));
    println!("Макс. одновременных соединений: {}", max_concurrent);
    
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let mut tasks = Vec::new();
    
    for ip_int in first..=last {
        let ip = u32_to_ip(ip_int);
        let port_spec_clone = port_spec.to_string();
        let sem_clone = semaphore.clone();
        
        tasks.push(tokio::spawn(async move {
            scan_single_host(ip, &port_spec_clone, sem_clone.available_permits()).await;
        }));
    }
    
    let _ = join_all(tasks).await;
}

#[tokio::main]
async fn main() {
    show_uptime();
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <ip[/mask]> <port|port-range>", args[0]);
        println!("Examples:");
        println!("  {} 192.168.1.1 80", args[0]);
        println!("  {} 192.168.1.0/24 80,443", args[0]);
        println!("  {} 10.0.0.0/8 22 (осторожно: большой диапазон!)", args[0]);
        return;
    }
    
    let ip_arg = &args[1];
    let port_arg = &args[2];
    let cores = num_cpus::get();
    
    println!("Обнаружено ядер CPU: {}", cores);
    
    let max_concurrent = if ip_arg.contains('/') && port_arg.contains('-') {
        500
    } else {
        (cores * 100).min(2000)
    };
    
    if ip_arg.contains('/') {
        scan_network(ip_arg, port_arg, max_concurrent).await;
    } else {
        scan_single_host(ip_arg.to_string(), port_arg, max_concurrent).await;
    }
    
    println!("\nСканирование завершено.");
    show_uptime();
}
