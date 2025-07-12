package com.example.cua_hang_xe_may.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Email;

/**
 * DTO for forgot password request
 */
public class ForgotPasswordRequest {
    @NotBlank(message = "Email không được để trống")
    @Email(message = "Email không đúng định dạng")
    private String email;

    public ForgotPasswordRequest() {
    }

    public ForgotPasswordRequest(String email) {
        this.email = email;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}