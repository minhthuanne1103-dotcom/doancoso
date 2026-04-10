use reqwest;
use rust_xlsxwriter::*;
use std::error::Error;
use std::io::{self, Read, Write}; 
use std::net::ToSocketAddrs;
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH}; 
use colored::*;

fn main() -> Result<(), Box<dyn Error>> {
    println!("{}", "===============================================".cyan());
    println!("{}", "     CONG CU QUET LO HONG WEB CHUYEN NGHIEP     ".yellow().bold());
    println!("{}", "===============================================".cyan());

    // 1. Nhập URL mục tiêu
    print!("[>] Nhap URL (vidu: testphp.vulnweb.com): ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let raw_target = input.trim().to_string();

    let target_url = if raw_target.starts_with("http") {
        raw_target.clone()
    } else {
        format!("http://{}", raw_target)
    };

    let domain_only = raw_target
        .replace("http://", "")
        .replace("https://", "")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();

    // 2. Khoi tao file Excel
    let mut workbook = Workbook::new();
    let sheet = workbook.add_worksheet();
    
    let format_critical = Format::new().set_font_color(Color::Red).set_bold();
    let format_high = Format::new().set_font_color(Color::Orange).set_bold();
    let format_medium = Format::new().set_font_color(Color::Yellow).set_bold();
    let format_header = Format::new().set_bold().set_background_color(Color::Gray);

    sheet.write_with_format(0, 0, "STT", &format_header)?;
    sheet.write_with_format(0, 1, "Hang Muc Kiem Tra", &format_header)?;
    sheet.write_with_format(0, 2, "Ket Qua & Phien Ban", &format_header)?; 
    sheet.write_with_format(0, 3, "Muc Do Nguy Hiem", &format_header)?;

    let mut row = 1;

    // 3. Quét các cổng & Nhận diện phiên bản (Port Scan & Banner Grabbing)
    println!("\n[*] Dang quet cac cong & phien ban tren: {}...", domain_only.blue());
    let ports = vec![21, 22, 23, 80, 443, 3306, 8080];

    for port in ports {
        let addr_str = format!("{}:{}", domain_only, port);
        print!("    Checking Port {}... ", port);
        
        let mut banner = String::from("Unknown");
        
        let status = match addr_str.to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                        Ok(mut stream) => {
                            println!("{}", "OPEN".green().bold());
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                            let mut buffer = [0; 1024];
                            if let Ok(n) = stream.read(&mut buffer) {
                                let response = String::from_utf8_lossy(&buffer[..n]);
                                banner = response.trim().replace('\n', " ").replace('\r', "");
                                if banner.is_empty() { banner = "MO (Khong co banner)".to_string(); }
                            } else {
                                banner = "MO (An danh)".to_string();
                            }
                            "OPEN"
                        },
                        Err(_) => {
                            println!("Closed");
                            "Closed"
                        }
                    }
                } else { "Loi dia chi" }
            }
            Err(_) => {
                println!("{}", "Loi DNS".red());
                "Khong the phan giai ten mien"
            }
        };

        sheet.write(row, 0, row as f64)?;
        sheet.write(row, 1, format!("Port {}", port))?;
        
        if status == "OPEN" {
            sheet.write(row, 2, &banner)?;
            match port {
                21 | 23 => { sheet.write_with_format(row, 3, "RAT CAO", &format_critical)?; }
                22 | 3306 => { sheet.write_with_format(row, 3, "CAO", &format_high)?; }
                8080 => { sheet.write_with_format(row, 3, "TRUNG BINH", &format_medium)?; }
                _ => { sheet.write(row, 3, "Thap")?; }
            }
        } else {
            sheet.write(row, 2, status)?;
            sheet.write(row, 3, "An toan")?;
        }
        row += 1;
    }

    // 4. Quét file nhạy cảm & TRÍCH XUẤT HTTP HEADER SERVER
    println!("\n[*] Dang quet file nhay cam tren: {}...", target_url.blue());
    let paths = vec![".env", "admin/", "config.php", "robots.txt", ".git/config", "backup.zip"];

    // Khởi tạo client để cấu hình timeout và headers dễ dàng hơn
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    for p in paths {
        let full_url = format!("{}/{}", target_url.trim_end_matches('/'), p);
        print!("    Scanning: {}... ", p);

        sheet.write(row, 0, row as f64)?;
        sheet.write(row, 1, &full_url)?;

        match client.get(&full_url).send() {
            Ok(res) => {
                // Lấy thông tin Server từ Header của phản hồi
                let server_ver = res.headers()
                    .get("server")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("Unknown Server");

                if res.status().is_success() {
                    println!("{}", "FOUND!".red().bold());
                    // Lưu kết quả kèm theo thông tin Server lấy được từ Header
                    sheet.write(row, 2, format!("200 OK (Server: {})", server_ver))?;
                    
                    match p {
                        ".env" | ".git/config" => {
                            sheet.write_with_format(row, 3, "RAT CAO", &format_critical)?;
                        },
                        "admin/" | "config.php" => {
                            sheet.write_with_format(row, 3, "CAO", &format_high)?;
                        },
                        "backup.zip" => {
                            sheet.write_with_format(row, 3, "TRUNG BINH", &format_medium)?;
                        },
                        _ => {
                            sheet.write(row, 3, "Thap")?;
                        }
                    }
                } else {
                    println!("Not found");
                    sheet.write(row, 2, format!("{} (Server: {})", res.status(), server_ver))?;
                    sheet.write(row, 3, "An toan")?;
                }
            }
            Err(_) => {
                println!("Error");
                sheet.write(row, 2, "Loi ket noi")?;
            }
        }
        row += 1;
    }

    // 5. TU DONG CAN CHINH
    sheet.autofit(); 

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    let file_name = format!("Bao_Cao_{}_{}.xlsx", domain_only.replace('.', "_"), timestamp);
    
    workbook.save(&file_name)?;

    println!("\n{}", "===============================================".green());
    println!("{} {}", "THANH CONG! File bao cao da luu tai:".green(), file_name.yellow().bold());
    println!("{}", "===============================================".green());

    Ok(())
}