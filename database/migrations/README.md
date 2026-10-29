# Database Migrations

Thư mục này được sử dụng để quản lý các file migration thay đổi cấu trúc bảng theo phiên bản (version-controlled database migrations).

## Quy ước đặt tên file
`YYYYMMDD_HHMMSS_<migration_description>.sql`

Ví dụ:
`20261007_010000_add_ml_features_to_logs.sql`

## Trạng thái hiện tại
Trong giai đoạn khởi tạo nền tảng, schema chính đã được định nghĩa tại `database/schema/01_init.sql` và dữ liệu mẫu tại `database/seed/01_seed.sql`.
Các thay đổi bảng sau này sẽ được bổ sung vào đây dưới dạng các script tuần tự.
