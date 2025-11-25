# WAF / ModSecurity Demo — Hướng dẫn

Mô tả nhanh
- Trang `WAFDemo` trong client liệt kê các payload phổ biến để kiểm tra hành vi Web Application Firewall (ModSecurity).
- Có sẵn một script curl tĩnh `client/public/waf-test-curl.sh` để tải về và chạy trong môi trường cô lập.

Lưu ý an toàn
- Chỉ chạy thử trong môi trường local/dev hoặc môi trường kiểm thử riêng. Không gửi payload này tới hệ thống production hoặc hệ thống bạn không được phép thử nghiệm.
- Tốt nhất chạy toàn bộ trong Docker network riêng hoặc VM.

Files được thêm
- `client/public/waf-test-curl.sh` — script chứa các curl examples. Thay `TARGET` trong file nếu cần.
- `docker/attacker/run-tests.sh` — script để chạy `waf-test-curl.sh` khi mount `client/public` vào container.
- `client/src/pages/WAFDemo.js` — UI demo với copy/open/curl và chế độ GET/POST/HEADER.

Chạy nhanh (không dùng Docker-compose)
1. Chạy app (client + server + proxy ModSecurity) theo cách bạn đã làm.
2. Tải file `waf-test-curl.sh` từ `http://<your-client-host>/waf-test-curl.sh` hoặc lấy từ `client/public/waf-test-curl.sh` trong code.
3. Chạy script trên máy dev (chỉ khi bạn biết TARGET là an toàn):

```bash
chmod +x waf-test-curl.sh
TARGET="http://localhost:8080" ./waf-test-curl.sh
```

Chạy bằng attacker container (ví dụ dùng alpine):

```bash
# giả sử repo root là current dir
docker run --rm -v %cd%/client/public:/data --network my_waf_net alpine:3.18 /data/run-tests.sh
```

Trong Windows `cmd.exe` thay `%cd%` bằng `%%cd%%` hoặc dựng đường dẫn đầy đủ.

Xem log ModSecurity
- Nếu bạn dùng Docker để chạy nginx+modsecurity, map thư mục log ra host (ví dụ `-v ./logs:/var/log/modsecurity`) để dễ đọc.
- Log audit ModSecurity thường ở `/var/log/modsec_audit.log` hoặc file cấu hình `modsecurity.conf`.

Thêm / Tùy chỉnh
- Bạn có thể mở `client/public/waf-test-curl.sh` và thay `TARGET` cho đúng host/port proxy.
- Nếu muốn chạy nhiều request nhanh để test rate-limiting hoặc detection, hãy dùng attacker container có `ab`/`wrk`/`curl` script hoặc một công cụ load testing.

Hỗ trợ
- Muốn tôi: (A) tạo `docker-compose.waf-demo.yml` để dựng full-stack gồm `proxy (nginx+modsecurity)`, `server`, `client`, `attacker`? (B) Hay chỉ muốn tôi thêm header/body examples lên UI? Trả lời "A" hoặc "B".
