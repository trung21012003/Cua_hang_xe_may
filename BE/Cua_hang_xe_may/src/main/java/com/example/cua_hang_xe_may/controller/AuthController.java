package com.example.cua_hang_xe_may.controller;

import com.example.cua_hang_xe_may.dto.ApiResponse;
import com.example.cua_hang_xe_may.dto.AuthRequest;
import com.example.cua_hang_xe_may.dto.ForgotPasswordRequest;
import com.example.cua_hang_xe_may.dto.RegisterRequest;
import com.example.cua_hang_xe_may.dto.ResetPasswordRequest;
import com.example.cua_hang_xe_may.entities.Account;
import com.example.cua_hang_xe_may.repositories.AccountRepository;
import com.example.cua_hang_xe_may.security.JwtUtil;
import com.example.cua_hang_xe_may.service.EmailService;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final AccountRepository accountRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager, 
                         AccountRepository accountRepository,
                         PasswordEncoder passwordEncoder,
                         EmailService emailService) {
        this.authenticationManager = authenticationManager;
        this.accountRepository = accountRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse> login(@Valid @RequestBody AuthRequest authRequest) {
        try {
            // Check if the account exists and is active before attempting authentication
            Optional<Account> accountOpt = accountRepository.findByUsername(authRequest.getUsername());
            if (accountOpt.isPresent()) {
                Account account = accountOpt.get();
                if ("PENDING".equals(account.getStatus())) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(new ApiResponse("Tài khoản chưa được kích hoạt. Vui lòng kiểm tra email để xác thực tài khoản.", false));
                }
            }

            // Xác thực người dùng
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
            );

            // Lưu thông tin xác thực vào SecurityContext
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Lấy thông tin người dùng từ Authentication
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            // Lấy role từ authorities (giả sử user chỉ có 1 role)
            String roleAuthority = userDetails.getAuthorities().stream()
                    .map(authority -> authority.getAuthority())
                    .findFirst()
                    .orElse("ROLE_USER"); // Mặc định là "ROLE_USER" nếu không tìm thấy role

            // Tạo JWT với username và role
            String jwt = JwtUtil.generateToken(authRequest.getUsername(), roleAuthority);

            Map<String, Object> data = new HashMap<>();
            data.put("token", jwt);
            data.put("role", roleAuthority);
            data.put("username", authRequest.getUsername());

            return ResponseEntity.ok(new ApiResponse("Login successful", true, data));
        } catch (Exception e) {
            // Check if the exception message contains information about account verification
            if (e.getMessage() != null && e.getMessage().contains("Account is not active")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ApiResponse("Tài khoản chưa được kích hoạt. Vui lòng kiểm tra email để xác thực tài khoản.", false));
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse("Tên đăng nhập hoặc mật khẩu không đúng", false));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse> register(@Valid @RequestBody RegisterRequest registerRequest) {
        // Check if username already exists
        if (accountRepository.existsByUsername(registerRequest.getUsername())) {
            return ResponseEntity.badRequest().body(
                new ApiResponse("Username is already taken", false)
            );
        }

        // Check if email already exists
        if (accountRepository.existsByEmail(registerRequest.getEmail())) {
            return ResponseEntity.badRequest().body(
                new ApiResponse("Email is already in use", false)
            );
        }

        // Create new account
        Account account = new Account();
        account.setUsername(registerRequest.getUsername());
        account.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        account.setEmail(registerRequest.getEmail());
        account.setPhone(registerRequest.getPhone());
        account.setName(registerRequest.getName());
        account.setDob(registerRequest.getDob());
        account.setAddress(registerRequest.getAddress());
        account.setRole("1"); // Default role is USER
        account.setStatus("PENDING"); // Account is pending until email is verified
        account.setCreated(Instant.now());

        // Generate security code for email verification
        String securityCode = UUID.randomUUID().toString();
        account.setSecurityCode(securityCode);

        // Save account
        accountRepository.save(account);

        // Send verification email
        try {
            emailService.sendVerificationEmail(account.getEmail(), securityCode);
            return ResponseEntity.ok(
                new ApiResponse("Registration successful. Please check your email to verify your account.", true)
            );
        } catch (MessagingException e) {
            // If email sending fails, still create the account but inform the user
            return ResponseEntity.status(HttpStatus.CREATED).body(
                new ApiResponse("Registration successful but failed to send verification email. Please contact support.", true)
            );
        }
    }

    @GetMapping("/verify")
    public ResponseEntity<?> verifyEmail(@RequestParam("code") String code) {
        Optional<Account> accountOpt = accountRepository.findBySecurityCode(code);

        if (accountOpt.isEmpty()) {
            // For invalid verification code, return a simple HTML error page
            String errorHtml = "<!DOCTYPE html>\n" +
                    "<html lang=\"vi\">\n" +
                    "<head>\n" +
                    "    <meta charset=\"UTF-8\">\n" +
                    "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
                    "    <title>Xác thực không thành công</title>\n" +
                    "    <style>\n" +
                    "        body {\n" +
                    "            font-family: 'Arial', sans-serif;\n" +
                    "            background-color: #f8f9fa;\n" +
                    "            color: #333;\n" +
                    "            display: flex;\n" +
                    "            justify-content: center;\n" +
                    "            align-items: center;\n" +
                    "            height: 100vh;\n" +
                    "            margin: 0;\n" +
                    "        }\n" +
                    "        .container {\n" +
                    "            background-color: white;\n" +
                    "            border-radius: 8px;\n" +
                    "            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);\n" +
                    "            padding: 40px;\n" +
                    "            text-align: center;\n" +
                    "            max-width: 500px;\n" +
                    "            width: 90%;\n" +
                    "        }\n" +
                    "        .icon {\n" +
                    "            color: #dc3545;\n" +
                    "            font-size: 64px;\n" +
                    "            margin-bottom: 20px;\n" +
                    "        }\n" +
                    "        h1 {\n" +
                    "            color: #dc3545;\n" +
                    "            margin-bottom: 20px;\n" +
                    "        }\n" +
                    "        p {\n" +
                    "            margin-bottom: 20px;\n" +
                    "            line-height: 1.6;\n" +
                    "        }\n" +
                    "        .btn {\n" +
                    "            display: inline-block;\n" +
                    "            background-color: #dc3545;\n" +
                    "            color: white;\n" +
                    "            padding: 10px 20px;\n" +
                    "            border-radius: 4px;\n" +
                    "            text-decoration: none;\n" +
                    "            font-weight: bold;\n" +
                    "            transition: background-color 0.3s;\n" +
                    "        }\n" +
                    "        .btn:hover {\n" +
                    "            background-color: #c82333;\n" +
                    "        }\n" +
                    "    </style>\n" +
                    "</head>\n" +
                    "<body>\n" +
                    "    <div class=\"container\">\n" +
                    "        <div class=\"icon\">❌</div>\n" +
                    "        <h1>Xác thực không thành công</h1>\n" +
                    "        <p>Mã xác thực không hợp lệ hoặc đã hết hạn.</p>\n" +
                    "        <p>Vui lòng kiểm tra lại email hoặc yêu cầu gửi lại mã xác thực.</p>\n" +
                    "        <a href=\"http://localhost:3000/login\" class=\"btn\">Quay lại trang đăng nhập</a>\n" +
                    "    </div>\n" +
                    "</body>\n" +
                    "</html>";
            return ResponseEntity.badRequest()
                    .header("Content-Type", "text/html; charset=UTF-8")
                    .body(errorHtml);
        }

        Account account = accountOpt.get();
        account.setStatus("ACTIVE"); // Activate the account
        account.setSecurityCode("VERIFIED"); // Clear the security code or mark as verified
        accountRepository.save(account);

        // Return a success HTML page
        String successHtml = "<!DOCTYPE html>\n" +
                "<html lang=\"vi\">\n" +
                "<head>\n" +
                "    <meta charset=\"UTF-8\">\n" +
                "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
                "    <title>Xác thực thành công</title>\n" +
                "    <style>\n" +
                "        body {\n" +
                "            font-family: 'Arial', sans-serif;\n" +
                "            background-color: #f8f9fa;\n" +
                "            color: #333;\n" +
                "            display: flex;\n" +
                "            justify-content: center;\n" +
                "            align-items: center;\n" +
                "            height: 100vh;\n" +
                "            margin: 0;\n" +
                "        }\n" +
                "        .container {\n" +
                "            background-color: white;\n" +
                "            border-radius: 8px;\n" +
                "            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);\n" +
                "            padding: 40px;\n" +
                "            text-align: center;\n" +
                "            max-width: 500px;\n" +
                "            width: 90%;\n" +
                "        }\n" +
                "        .icon {\n" +
                "            color: #28a745;\n" +
                "            font-size: 64px;\n" +
                "            margin-bottom: 20px;\n" +
                "        }\n" +
                "        h1 {\n" +
                "            color: #28a745;\n" +
                "            margin-bottom: 20px;\n" +
                "        }\n" +
                "        p {\n" +
                "            margin-bottom: 20px;\n" +
                "            line-height: 1.6;\n" +
                "        }\n" +
                "        .btn {\n" +
                "            display: inline-block;\n" +
                "            background-color: #dc3545;\n" +
                "            color: white;\n" +
                "            padding: 10px 20px;\n" +
                "            border-radius: 4px;\n" +
                "            text-decoration: none;\n" +
                "            font-weight: bold;\n" +
                "            transition: background-color 0.3s;\n" +
                "        }\n" +
                "        .btn:hover {\n" +
                "            background-color: #c82333;\n" +
                "        }\n" +
                "        .countdown {\n" +
                "            font-size: 14px;\n" +
                "            color: #6c757d;\n" +
                "            margin-top: 20px;\n" +
                "        }\n" +
                "    </style>\n" +
                "</head>\n" +
                "<body>\n" +
                "    <div class=\"container\">\n" +
                "        <div class=\"icon\">✅</div>\n" +
                "        <h1>Xác thực thành công</h1>\n" +
                "        <p>Tài khoản của bạn đã được kích hoạt thành công.</p>\n" +
                "        <p>Bạn có thể đăng nhập ngay bây giờ.</p>\n" +
                "        <a href=\"http://localhost:5173/login\" class=\"btn\">Đăng nhập</a>\n" +
                "        <p class=\"countdown\">Tự động chuyển hướng đến trang đăng nhập sau <span id=\"timer\">5</span> giây</p>\n" +
                "    </div>\n" +
                "    <script>\n" +
                "        // Countdown timer and redirect\n" +
                "        let seconds = 5;\n" +
                "        const timerElement = document.getElementById('timer');\n" +
                "        const countdown = setInterval(() => {\n" +
                "            seconds--;\n" +
                "            timerElement.textContent = seconds;\n" +
                "            if (seconds <= 0) {\n" +
                "                clearInterval(countdown);\n" +
                "                window.location.href = 'http://localhost:5173/login';\n" +
                "            }\n" +
                "        }, 1000);\n" +
                "    </script>\n" +
                "</body>\n" +
                "</html>";

        return ResponseEntity.ok()
                .header("Content-Type", "text/html; charset=UTF-8")
                .body(successHtml);
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<ApiResponse> resendVerification(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        if (email == null || email.isEmpty()) {
            return ResponseEntity.badRequest().body(
                    new ApiResponse("Email không được để trống", false)
            );
        }

        Optional<Account> accountOpt = accountRepository.findByEmail(email);
        if (accountOpt.isEmpty()) {
            return ResponseEntity.badRequest().body(
                    new ApiResponse("Không tìm thấy tài khoản với email này", false)
            );
        }

        Account account = accountOpt.get();

        // Nếu tài khoản đã được kích hoạt
        if ("ACTIVE".equals(account.getStatus())) {
            return ResponseEntity.badRequest().body(
                    new ApiResponse("Tài khoản đã được kích hoạt", false)
            );
        }

        // Tạo mã xác nhận mới
        String securityCode = UUID.randomUUID().toString();
        account.setSecurityCode(securityCode);
        accountRepository.save(account);

        // Gửi email xác nhận
        try {
            emailService.sendVerificationEmail(account.getEmail(), securityCode);
            return ResponseEntity.ok(
                    new ApiResponse("Mã xác nhận mới đã được gửi đến email của bạn", true)
            );
        } catch (MessagingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    new ApiResponse("Không thể gửi email xác nhận. Vui lòng thử lại sau", false)
            );
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        String email = request.getEmail();
        if (email == null || email.isEmpty()) {
            return ResponseEntity.badRequest().body(
                    new ApiResponse("Email không được để trống", false)
            );
        }

        Optional<Account> accountOpt = accountRepository.findByEmail(email);
        if (accountOpt.isEmpty()) {
            // For security reasons, don't reveal that the email doesn't exist
            return ResponseEntity.ok(
                    new ApiResponse("Nếu email tồn tại, hướng dẫn đặt lại mật khẩu sẽ được gửi đến email của bạn", true)
            );
        }

        Account account = accountOpt.get();

        // Generate reset token
        String resetToken = UUID.randomUUID().toString();
        account.setSecurityCode(resetToken);
        accountRepository.save(account);

        // Send password reset email
        try {
            emailService.sendPasswordResetEmail(account.getEmail(), resetToken);
            return ResponseEntity.ok(
                    new ApiResponse("Hướng dẫn đặt lại mật khẩu đã được gửi đến email của bạn", true)
            );
        } catch (MessagingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                    new ApiResponse("Không thể gửi email đặt lại mật khẩu. Vui lòng thử lại sau", false)
            );
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        String token = request.getToken();
        String newPassword = request.getNewPassword();

        if (token == null || token.isEmpty()) {
            return ResponseEntity.badRequest().body(
                    new ApiResponse("Token không hợp lệ", false)
            );
        }

        if (newPassword == null || newPassword.isEmpty()) {
            return ResponseEntity.badRequest().body(
                    new ApiResponse("Mật khẩu mới không được để trống", false)
            );
        }

        Optional<Account> accountOpt = accountRepository.findBySecurityCode(token);
        if (accountOpt.isEmpty()) {
            return ResponseEntity.badRequest().body(
                    new ApiResponse("Token không hợp lệ hoặc đã hết hạn", false)
            );
        }

        Account account = accountOpt.get();

        // Update password, clear security code, and ensure account is active
        account.setPassword(passwordEncoder.encode(newPassword));
        account.setSecurityCode("RESET_COMPLETED");
        account.setStatus("ACTIVE"); // Ensure account is active after password reset
        accountRepository.save(account);

        return ResponseEntity.ok(
                new ApiResponse("Mật khẩu đã được đặt lại thành công", true)
        );
    }

    @GetMapping("/reset-password")
    public ResponseEntity<?> verifyResetToken(@RequestParam("token") String token) {
        Optional<Account> accountOpt = accountRepository.findBySecurityCode(token);

        if (accountOpt.isEmpty()) {
            // For invalid token, return a simple HTML error page
            String errorHtml = "<!DOCTYPE html>\n" +
                    "<html lang=\"vi\">\n" +
                    "<head>\n" +
                    "    <meta charset=\"UTF-8\">\n" +
                    "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
                    "    <title>Token không hợp lệ</title>\n" +
                    "    <style>\n" +
                    "        body {\n" +
                    "            font-family: 'Arial', sans-serif;\n" +
                    "            background-color: #f8f9fa;\n" +
                    "            color: #333;\n" +
                    "            display: flex;\n" +
                    "            justify-content: center;\n" +
                    "            align-items: center;\n" +
                    "            height: 100vh;\n" +
                    "            margin: 0;\n" +
                    "        }\n" +
                    "        .container {\n" +
                    "            background-color: white;\n" +
                    "            border-radius: 8px;\n" +
                    "            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);\n" +
                    "            padding: 40px;\n" +
                    "            text-align: center;\n" +
                    "            max-width: 500px;\n" +
                    "            width: 90%;\n" +
                    "        }\n" +
                    "        .icon {\n" +
                    "            color: #dc3545;\n" +
                    "            font-size: 64px;\n" +
                    "            margin-bottom: 20px;\n" +
                    "        }\n" +
                    "        h1 {\n" +
                    "            color: #dc3545;\n" +
                    "            margin-bottom: 20px;\n" +
                    "        }\n" +
                    "        p {\n" +
                    "            margin-bottom: 20px;\n" +
                    "            line-height: 1.6;\n" +
                    "        }\n" +
                    "        .btn {\n" +
                    "            display: inline-block;\n" +
                    "            background-color: #dc3545;\n" +
                    "            color: white;\n" +
                    "            padding: 10px 20px;\n" +
                    "            border-radius: 4px;\n" +
                    "            text-decoration: none;\n" +
                    "            font-weight: bold;\n" +
                    "            transition: background-color 0.3s;\n" +
                    "        }\n" +
                    "        .btn:hover {\n" +
                    "            background-color: #c82333;\n" +
                    "        }\n" +
                    "    </style>\n" +
                    "</head>\n" +
                    "<body>\n" +
                    "    <div class=\"container\">\n" +
                    "        <div class=\"icon\">❌</div>\n" +
                    "        <h1>Token không hợp lệ</h1>\n" +
                    "        <p>Token đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.</p>\n" +
                    "        <p>Vui lòng yêu cầu đặt lại mật khẩu mới.</p>\n" +
                    "        <a href=\"http://localhost:5173/forgot-password\" class=\"btn\">Quên mật khẩu</a>\n" +
                    "    </div>\n" +
                    "</body>\n" +
                    "</html>";
            return ResponseEntity.badRequest()
                    .header("Content-Type", "text/html; charset=UTF-8")
                    .body(errorHtml);
        }

        // Redirect to the frontend reset password page with the token
        return ResponseEntity.status(HttpStatus.FOUND)
                .header("Location", "http://localhost:5173/reset-password?token=" + token)
                .build();
    }
}
