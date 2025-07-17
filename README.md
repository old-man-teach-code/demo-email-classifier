# Email Classifier

## Giới thiệu

Dự án này giúp **phân loại email** thành các nhóm như: An toàn, Nghi ngờ, Spam, Giả mạo dựa trên nội dung và địa chỉ gửi. Bạn có thể kiểm tra email mẫu hoặc tự thay đổi nội dung để kiểm thử.

## Yêu cầu

- Node.js >= 14
    ```

## Hướng dẫn sử dụng file test.js

1. **Mở file `test.js`**  
   Tìm đoạn sau:
   ````javascript
   const email = {
       title: "Thông báo khẩn từ ngân hàng",
       content: "Chúng tôi phát hiện có hoạt động đáng ngờ trên tài khoản của bạn. Vui lòng đăng nhập để xác nhận thông tin.",
       from_email: "no-reply@bank.com",
   }
   ````
   Bạn có thể thay đổi nội dung email này để kiểm thử.      
   Sửa đổi các trường `title`, `content`, `from_email` để thử nghiệm với các email khác nhau.
   Ví dụ:
   ```javascript
   const email = {
       title: "Khuyến mãi đặc biệt chỉ hôm nay!",
       content: "Nhấn vào đây để nhận quà tặng miễn phí.",
       from_email: "no-reply@promotion.com" // Thay đổi địa chỉ email
   }
   ```  
2. **Chạy file `test.js`**
    Mở Terminal và chạy lệnh:
    ```sh
    node test.js
    ```
    Kết quả phân loại sẽ được in ra console.        
3. **Kiểm tra kết quả**
    Kết quả sẽ cho biết email thuộc loại nào (An toàn, Nghi ngờ, Spam, Giả mạo) và các chỉ số liên quan.    
     