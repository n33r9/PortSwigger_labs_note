

# Path Traversal (6 labs)

**Định nghĩa:** **Path Traversal** (còn gọi là **Directory Traversal**) là lỗ hổng xảy ra khi ứng dụng cho phép người dùng kiểm soát đường dẫn tệp (file path), và không lọc đầu vào cẩn thận, cho phép attacker truy cập hoặc đọc các file **ngoài phạm vi dự kiến** trên máy chủ.

Ví dụ:

```
GET /?file=../../../../etc/passwd
```

→ Truy cập file chứa danh sách người dùng hệ thống Linux.

**Nguyên nhân:** 

- Nối trực tiếp input người dùng vào đường dẫn: Không lọc `..` hoặc ký tự `/`
- Thiếu kiểm tra whitelist tên file: Cho phép người dùng chọn file tùy ý
- Không chuẩn hóa đường dẫn: Dễ bị bypass bằng encoding
- Phụ thuộc vào blacklist đơn giản: `..`, `%2e`, `%252e`, v.v. có thể bypass

**Tác động:**

- Rò rỉ thông tin: Đọc file cấu hình (.env, config.php)

  VD: Nếu ứng dụng nối trực tiếp giá trị người dùng cung cấp với đường dẫn:

  ```php
  include("pages/" . $_GET['page'] . ".php");
  ```

  - Input: `../../../../etc/passwd%00`
  - Output: `/pages/../../../../etc/passwd` (→ thành `/etc/passwd`)

  => Nếu không kiểm soát kỹ, attacker có thể đọc toàn bộ hệ thống tệp.

- Lộ thông tin nhạy cảm: Credentials database, secret tokens

- Xem mã nguồn: Tìm lỗi logic, backdoor

- Kết hợp với file upload → RCE: Đọc và chạy file PHP upload

**Kỹ thuật khai thác:**

1. **URL-encoding**
   - `%2e` = `.`, `%2f` = `/`
   - `..%2f..%2fetc/passwd`
2. **Double encoding**
   - `%252e` → `%25` = `%`, `%2e` = `.`
   - Trình decode sẽ biến `%252e` thành `%2e`, rồi thành `.`
3. **Dot bypass**
   - `....//....//etc/passwd`
   - Vượt qua kiểm tra đơn giản `strpos(“..”)`
4. **Null byte injection (cũ)**
   - `../../etc/passwd%00.jpg`
   - Giúp cắt phần mở rộng giả như `.jpg` trên hệ thống C-based

**Phòng tránh:** 

- Không cho người dùng nhập đường dẫn trực tiếp: Dùng ID hoặc map cố định
  - `$filename = getFileFromId($_GET['id']);`
- Chuẩn hóa và kiểm tra đường dẫn: Dùng realpath() để chắc chắn file nằm trong thư mục cho phép
- Chặn `..`, `/`, `\` và các biến thể encode: Phát hiện traversal từ sớm
- Phân quyền file hệ thống đúng: Không cho app user đọc file hệ thống hoặc private file

Ví dụ kiểm tra chuẩn hóa đường dẫn trong PHP:

```php
phpCopy code$base = realpath("files/");
$target = realpath("files/" . $_GET['file']);

if (strpos($target, $base) !== 0) {
    die("Access denied!");
}
```

Common Payload:

- Truy cập `/etc/passwd`: `../../../../etc/passwd`
- Truy cập file hiện tại: `./config.php`
- Directory traversal encoded: `%2e%2e/%2e%2e/%2e%2e/etc/passwd`
- Windows traversal: `..\\..\\..\\boot.ini`
- Bypass filter bằng `.`: `....//....//etc/passwd`
- Double URL encode: `%252e%252e%252fetc/passwd`

## Apprentice 

### [Lab 1: File path traversal, simple case](https://portswigger.net/web-security/file-path-traversal/lab-simple)

Lab des: 

Khai thác lỗ hổng **Path Traversal** để đọc file **`/etc/passwd`** từ máy chủ.

Ứng dụng có chức năng hiển thị hình ảnh sản phẩm qua URL dạng:

![image-20250604022343107](./image/image-20250604022343107.png)

Nếu tham số `filename` không được xử lí đúng cách, có thể lợi dụng **`../` (directory traversal)** để truy cập file ngoài thư mục gốc (root directory của web app).

Steps: 

![image-20250604023150956](./image/image-20250604023150956.png)

![image-20250604023216072](./image/image-20250604023216072.png)



## Practitioner

### [Lab 1: File path traversal, traversal sequences blocked with absolute path bypass](https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass)

Lab des: 

- Ứng dụng có chức năng hiển thị ảnh sản phẩm.

- Ứng dụng **chặn các chuỗi traversal** như `../`, nhưng **cho phép cung cấp đường dẫn tuyệt đối**.

- File ảnh được truy cập qua endpoint như:

```
GET /image?filename=26.jpg
```

Steps: 

![image-20250604023911890](./image/image-20250604023911890.png)

![image-20250604023935427](./image/image-20250604023935427.png)



### [Lab 2: File path traversal, traversal sequences stripped non-recursively](https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively)

Lab des: 

Ứng dụng loại bỏ các chuỗi traversal như `../`, nhưng xử lý không kỹ.

Thử test với 2 payload của 2 bài lab trước: 

![image-20250604024701628](./image/image-20250604024701628.png)

=> No such file

Steps: 

![image-20250604024754109](./image/image-20250604024754109.png)

Có thể thuật toán strip là: Gặp `../` => auto strip = sau khi strip xong thì ta có đường dẫn tương đối  `../../../etc/paswd`

![image-20250604024804996](./image/image-20250604024804996.png)



### [Lab 3: File path traversal, traversal sequences stripped with superfluous URL-decode](https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode)

Lab des: 

Ứng dụng chặn các req có chứa chuỗi path traversal => decode url => gửi response

Steps: 

![image-20250604025643401](./image/image-20250604025643401.png)

![image-20250604025655043](./image/image-20250604025655043.png)



### [Lab 4: File path traversal, validation of start of path](https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path)

Lab des: 

- Ứng dụng yêu cầu client **truyền full path** qua tham số `filename`.

![image-20250604030548420](./image/image-20250604030548420.png)

- Server chỉ **kiểm tra xem đường dẫn có bắt đầu bằng `/var/www/images/`** không.

- Sau đó, **không kiểm tra gì thêm** và thực hiện truy cập file.

Steps: 

![image-20250604030430213](./image/image-20250604030430213.png)

![image-20250604030502431](./image/image-20250604030502431.png)



### [Lab 5: File path traversal, validation of file extension with null byte bypass](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass)

Lab des:

- Ứng dụng chỉ kiểm tra xem file ảnh có kết thúc bằng extensions mong muốn không (jpg || png)

Steps: 

![image-20250604031240352](./image/image-20250604031240352.png)

=> sau khi check extension xong, đến đoạn traverse file path, các hàm xử lí chuỗi sẽ cắt chuỗi khi gặp null byte

![image-20250604031258001](./image/image-20250604031258001.png)

