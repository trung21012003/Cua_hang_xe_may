package com.example.cua_hang_xe_may.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * DTO for reset password request
 */
public class ResetPasswordRequest {
    @NotBlank(message = "Token không được để trống")
    private String token;
    
    @NotBlank(message = "Mật khẩu mới không được để trống")
    @Size(min = 6, max = 100, message = "Mật khẩu mới phải có độ dài từ 6 đến 100 ký tự")
    private String newPassword;

    public ResetPasswordRequest() {
    }

    public ResetPasswordRequest(String token, String newPassword) {
        this.token = token;
        this.newPassword = newPassword;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}