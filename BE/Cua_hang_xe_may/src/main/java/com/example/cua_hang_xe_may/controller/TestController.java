package com.example.cua_hang_xe_may.controller;

import com.example.cua_hang_xe_may.service.EmailService;
import jakarta.mail.MessagingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/test")
public class TestController {

    @Autowired
    private EmailService emailService;

    /**
     * Test endpoint to send a test email
     * 
     * @param email the email address to send the test email to
     * @return a response indicating success or failure
     */
    @GetMapping("/send-email")
    public ResponseEntity<?> sendTestEmail(@RequestParam String email) {
        try {
            System.out.println("Received request to send test email to: " + email);
            emailService.sendTestEmail(email);
            return ResponseEntity.ok("Test email sent successfully to " + email);
        } catch (MessagingException e) {
            System.err.println("Error sending test email: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.badRequest().body("Failed to send test email: " + e.getMessage());
        }
    }
}