package com.example.cua_hang_xe_may.dto;

import lombok.Data;
import jakarta.validation.constraints.*;

import java.time.Instant;

@Data
public class RegisterRequest {
    @NotBlank(message = "Username không được để trống")
    @Size(min = 3, max = 50, message = "Username phải có độ dài từ 3 đến 50 ký tự")
    private String username;
    
    @NotBlank(message = "Password không được để trống")
    @Size(min = 6, max = 100, message = "Password phải có độ dài từ 6 đến 100 ký tự")
    private String password;
    
    @NotBlank(message = "Email không được để trống")
    @Email(message = "Email không đúng định dạng")
    private String email;
    
    @Pattern(regexp = "^$|^[0-9]{10,11}$", message = "Số điện thoại phải có 10-11 chữ số hoặc để trống")
    private String phone;
    
    @NotBlank(message = "Tên không được để trống")
    @Size(min = 2, max = 100, message = "Tên phải có độ dài từ 2 đến 100 ký tự")
    private String name;
    
    @Past(message = "Ngày sinh phải là ngày trong quá khứ")
    private Instant dob;
    
    @Size(max = 255, message = "Địa chỉ không được vượt quá 255 ký tự")
    private String address;
}