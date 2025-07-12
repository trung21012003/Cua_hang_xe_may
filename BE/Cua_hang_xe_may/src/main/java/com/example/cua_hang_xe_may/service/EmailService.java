package com.example.cua_hang_xe_may.service;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.beans.factory.annotation.Value;

import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;


    @Value("${spring.mail.username}")
    private String fromEmail;

    /**
     * Send an email with HTML content
     * 
     * @param to      recipient email address
     * @param subject email subject
     * @param content HTML content of the email
     * @throws MessagingException if there's an error sending the email
     */
    public void sendHtmlEmail(String to, String subject, String content) throws MessagingException {

        try {
            System.out.println("Sending HTML email to: " + to);
            System.out.println("Subject: " + subject);

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(content, true); // true indicates HTML content

            System.out.println("Email prepared, sending...");
            mailSender.send(message);
            System.out.println("Email sent successfully to " + to);
        } catch (Exception e) {
            System.err.println("Error sending HTML email: " + e.getMessage());
            e.printStackTrace();
            throw new MessagingException("Error sending HTML email", e);
        }

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(content, true); // true indicates HTML content

        mailSender.send(message);

    }

    /**
     * Send a verification email with a verification link
     * 
     * @param to            recipient email address
     * @param verificationCode the verification code
     * @throws MessagingException if there's an error sending the email
     */
    public void sendVerificationEmail(String to, String verificationCode) throws MessagingException {
        String subject = "Xác thực Email";
        String verificationLink = "http://localhost:8080/api/auth/verify?code=" + verificationCode;

        String content = "<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>"
                + "<h2 style='color: #333;'>Xác thực Email</h2>"
                + "<p>Cảm ơn bạn đã đăng ký. Vui lòng nhấp vào liên kết bên dưới để xác thực địa chỉ email của bạn:</p>"
                + "<p><a href='" + verificationLink + "' style='display: inline-block; padding: 10px 20px; "
                + "background-color: #dc3545; color: white; text-decoration: none; border-radius: 5px;'>"
                + "Xác thực Email</a></p>"
                + "<p>Hoặc sao chép và dán URL sau vào trình duyệt của bạn:</p>"
                + "<p>" + verificationLink + "</p>"
                + "<p>Liên kết này sẽ hết hạn sau 24 giờ.</p>"
                + "<p>Nếu bạn không đăng ký tài khoản, vui lòng bỏ qua email này.</p>"
                + "</div>";

        sendHtmlEmail(to, subject, content);
    }

    /**
     * Send a password reset email with a reset link
     * 
     * @param to            recipient email address
     * @param resetToken    the reset token
     * @throws MessagingException if there's an error sending the email
     */
    public void sendPasswordResetEmail(String to, String resetToken) throws MessagingException {
        String subject = "Đặt lại mật khẩu";
        String resetLink = "http://localhost:5173/reset-password?token=" + resetToken;

        String content = "<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>"
                + "<h2 style='color: #333;'>Đặt lại mật khẩu</h2>"
                + "<p>Bạn đã yêu cầu đặt lại mật khẩu. Vui lòng nhấp vào liên kết bên dưới để đặt lại mật khẩu của bạn:</p>"
                + "<p><a href='" + resetLink + "' style='display: inline-block; padding: 10px 20px; "
                + "background-color: #dc3545; color: white; text-decoration: none; border-radius: 5px;'>"
                + "Đặt lại mật khẩu</a></p>"
                + "<p>Hoặc sao chép và dán URL sau vào trình duyệt của bạn:</p>"
                + "<p>" + resetLink + "</p>"
                + "<p>Liên kết này sẽ hết hạn sau 1 giờ.</p>"
                + "<p>Nếu bạn không yêu cầu đặt lại mật khẩu, vui lòng bỏ qua email này.</p>"
                + "</div>";

        sendHtmlEmail(to, subject, content);
    }


    /**
     * Send a test email to verify the email configuration
     * 
     * @param to recipient email address
     * @throws MessagingException if there's an error sending the email
     */
    public void sendTestEmail(String to) throws MessagingException {
        try {
            System.out.println("Sending test email to: " + to);
            String subject = "Test Email";
            String content = "<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>"
                    + "<h2 style='color: #333;'>Test Email</h2>"
                    + "<p>This is a test email to verify the email configuration.</p>"
                    + "<p>If you received this email, the email configuration is working correctly.</p>"
                    + "</div>";

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(content, true); // true indicates HTML content

            System.out.println("Test email prepared, sending...");
            mailSender.send(message);
            System.out.println("Test email sent successfully to " + to);
        } catch (Exception e) {
            System.err.println("Error sending test email: " + e.getMessage());
            e.printStackTrace();
            throw new MessagingException("Error sending test email", e);
        }
    }

}
