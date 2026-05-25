#[macro_use] extern crate rocket;

use rocket::fs::{relative, FileServer};
use rocket::http::{ContentType, Header, Status};
use rocket::response::{self, Responder, Response};
use rocket::Request;
use std::net::{ToSocketAddrs, TcpStream};
use std::io::{Cursor, Read, Write};
use std::time::Duration;
use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use rust_xlsxwriter::{Workbook, Format, Color as XlsxColor};

pub struct ExcelReport {
    data: Vec<u8>,
    filename: String,
}

#[rocket::async_trait]
impl<'r> Responder<'r, 'static> for ExcelReport {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        Response::build()
            .status(Status::Ok)
            .header(ContentType::new("application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
            .header(Header::new("Content-Disposition", format!("attachment; filename=\"{}\"", self.filename)))
            .sized_body(self.data.len(), Cursor::new(self.data))
            .ok()
    }
}

fn get_version(addr: &std::net::SocketAddr) -> String {
    let timeout = Duration::from_millis(800);
    if let Ok(mut stream) = TcpStream::connect_timeout(addr, timeout) {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(800)));
        let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\n");
        
        let mut buffer = [0; 128];
        if let Ok(size) = stream.read(&mut buffer) {
            let banner = String::from_utf8_lossy(&buffer[..size]);
            return banner.lines().next().unwrap_or("Unknown").trim().to_string();
        }
    }
    "N/A (No Banner)".to_string()
}

// Hàm phụ trợ thực hiện quét một danh sách cổng cụ thể bằng đa luồng
fn scan_port_list(ports: Vec<u16>, domain: &str, timeout: Duration, results: Arc<Mutex<Vec<(u16, bool, String)>>>) {
    let mut handles = vec![];
    for port in ports {
        let domain_clone = domain.to_string();
        let results_clone = Arc::clone(&results);
        
        handles.push(thread::spawn(move || {
            let addr_str = format!("{}:{}", domain_clone, port);
            let mut status = false;
            let mut version = String::from("N/A");
            
            if let Ok(mut addrs) = addr_str.to_socket_addrs() {
                if let Some(a) = addrs.next() {
                    if let Ok(_) = TcpStream::connect_timeout(&a, timeout) {
                        status = true;
                        version = get_version(&a);
                    }
                }
            }
            let mut data = results_clone.lock().unwrap();
            data.push((port, status, version));
        }));
    }
    for h in handles {
        let _ = h.join();
    }
}

#[get("/scan?<url>")]
async fn scan(url: String) -> Result<ExcelReport, Status> {
    let domain_only = url.trim()
        .replace("http://", "").replace("https://", "")
        .split('/').next().unwrap_or("").to_string();

    if domain_only.is_empty() { return Err(Status::BadRequest); }

    let results = Arc::new(Mutex::new(Vec::new()));
    
    // CHỈNH SỬA 1: Giảm từ 300ms xuống 100ms để tăng tốc độ phản hồi, tránh treo trang web
    let timeout = Duration::from_millis(100);

    //7 cổng trọng điểm cần tập trung ưu tiên
    let priority_ports: HashSet<u16> = [21, 22, 23, 80, 443, 3306, 8080].iter().cloned().collect();
    
    println!("=== GIAI ĐOẠN 1: Quét tập trung 7 cổng ưu tiên cho: {} ===", domain_only);
    let priority_vector: Vec<u16> = priority_ports.iter().cloned().collect();
    scan_port_list(priority_vector, &domain_only, timeout, Arc::clone(&results));

    println!("=== GIAI ĐOẠN 2: Quét nền toàn bộ các cổng còn lại ===");
    let total_ports = 65535;
    let batch_size = 500;

    for chunk_start in (1..=total_ports).step_by(batch_size) {
        let chunk_end = std::cmp::min(chunk_start + batch_size - 1, total_ports);
        
        // CHỈNH SỬA 2: In tiến độ ra Terminal để biết hệ thống vẫn đang chạy bình thường, không bị đóng băng
        if chunk_start % 5000 == 1 {
            println!("-> Tiến độ: Đang quét dải cổng từ {} đến {}...", chunk_start, std::cmp::min(chunk_start + 4999, total_ports));
        }
        
        // Chỉ lọc lấy các cổng KHÔNG nằm trong danh sách 7 cổng đã quét
        let remaining_ports: Vec<u16> = (chunk_start..=chunk_end)
            .map(|p| p as u16)
            .filter(|p| !priority_ports.contains(p))
            .collect();

        if !remaining_ports.is_empty() {
            scan_port_list(remaining_ports, &domain_only, timeout, Arc::clone(&results));
        }
    }

    // Sắp xếp đẩy cổng OPEN (true) lên đầu, CLOSED (false) xuống dưới.
    // Nếu cùng trạng thái, sắp xếp tăng dần theo số hiệu cổng.
    let mut final_data = results.lock().unwrap();
    final_data.sort_by(|a, b| {
        let status_a = a.1;
        let status_b = b.1;
        
        status_b.cmp(&status_a).then_with(|| a.0.cmp(&b.0))
    });

    let mut workbook = Workbook::new();
    let sheet = workbook.add_worksheet();
    
    let format_header = Format::new().set_bold().set_background_color(XlsxColor::Gray);
    let format_red = Format::new().set_font_color(XlsxColor::Red).set_bold();
    let format_blue = Format::new().set_font_color(XlsxColor::Blue);

    let headers = ["STT", "Cổng (Port)", "Trạng thái", "Phiên bản (Version)", "Mức độ nguy hiểm (CVSS)"];
    for (i, h) in headers.iter().enumerate() {
        let _ = sheet.write_with_format(0, i as u16, *h, &format_header);
    }

    for (i, (port, is_open, version)) in final_data.iter().enumerate() {
        let row = (i + 1) as u32;
        let _ = sheet.write(row, 0, row as f64);
        let _ = sheet.write(row, 1, *port as f64);
        
        if *is_open {
            let _ = sheet.write_with_format(row, 2, "OPEN", &format_red);
            let _ = sheet.write(row, 3, version);
            
            // Cập nhật đánh giá rủi ro bao gồm cả các cổng bạn yêu cầu
            let risk = match port {
                22 => "Nguy hiểm (7.5) - Dịch vụ SSH",
                21 | 23 => "Nguy hiểm (7.5) - Giao thức không mã hóa",
                80 | 8080 | 3306 => "Bình Thường (5.0) - Cần kiểm tra quyền truy cập",
                443 => "Thấp (3.0) - HTTPS an toàn",
                _ => "UNKNOWN"
            };
            let _ = sheet.write(row, 4, risk);
        } else {
            let _ = sheet.write_with_format(row, 2, "CLOSED", &format_blue);
            let _ = sheet.write(row, 3, "N/A");
            let _ = sheet.write(row, 4, "An toàn (0.0)");
        }
    }

    sheet.autofit();
    let buffer = workbook.save_to_buffer().map_err(|_| Status::InternalServerError)?;
    Ok(ExcelReport { data: buffer, filename: format!("Report_{}.xlsx", domain_only) })
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    rocket::build()
        .mount("/", FileServer::from(relative!("static")))
        .mount("/", routes![scan])
        .launch()
        .await?;

    Ok(())
}