# F0ND67 script trên Vercel

Cấu trúc:
- index.html  : giao diện (không còn Firebase)
- api/index.js: máy chủ (đăng nhập, bài đăng, thích, lượt xem, quản trị)
- vercel.json, package.json

## Cài đặt (không cần GitHub)

1. Cài Node.js, rồi chạy: npm i -g vercel
2. Đăng nhập: vercel login
3. Vào thư mục này, chạy: vercel
   (trả lời các câu hỏi, đặt tên dự án là f0ndhub)
4. Trên trang vercel.com mở dự án > Storage > Create Database > chọn Upstash (Redis) > Connect to Project.
   Vercel tự thêm biến KV_REST_API_URL và KV_REST_API_TOKEN.
5. Dự án > Settings > Environment Variables, thêm:
   - SESSION_SECRET : một chuỗi ngẫu nhiên dài ít nhất 32 ký tự
   - ADMIN_USERNAME : tên đăng nhập của bạn (chữ thường, a-z 0-9 _)
6. Chạy: vercel --prod
7. Mở web, ĐĂNG KÝ NGAY tài khoản có đúng tên ADMIN_USERNAME. Tài khoản này là admin.

Đổi biến môi trường xong phải chạy lại: vercel --prod
