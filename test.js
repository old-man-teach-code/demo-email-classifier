const {analyzeEmail} = require('./email-classifier');

const email = {
    title: "Thông báo khẩn từ ngân hàng",
    content: "Chúng tôi phát hiện có hoạt động đáng ngờ trên tài khoản của bạn. Vui lòng đăng nhập để xác nhận thông tin.",
    from_email: "no-reply@bank.com",
}

const analysisResult = analyzeEmail(email);
console.log(analysisResult);