package com.example.cua_hang_xe_may.dto;

import lombok.Data;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Data
public class AuthRequest {
    @NotBlank(message = "Username không được để trống")
    private String username;
    
    @NotBlank(message = "Password không được để trống")
    private String password;
}