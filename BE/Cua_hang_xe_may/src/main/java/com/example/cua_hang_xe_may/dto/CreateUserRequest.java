package com.example.cua_hang_xe_may.dto;

import lombok.Data;

@Data
public class CreateUserRequest {
    private String username;
    private String password;
    private String email;
    private String phone;
    private String name;
    private String address;
    private String role;

import jakarta.validation.constraints.*;

@Data
public class CreateUserRequest {
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
    
    @Size(max = 255, message = "Địa chỉ không được vượt quá 255 ký tự")
    private String address;
    
    @NotBlank(message = "Role không được để trống")
    @Pattern(regexp = "^(USER|ADMIN|MANAGER)$", message = "Role phải là USER, ADMIN hoặc MANAGER")
    private String role;
    
    @NotBlank(message = "Status không được để trống")
    @Pattern(regexp = "^(ACTIVE|INACTIVE|SUSPENDED)$", message = "Status phải là ACTIVE, INACTIVE hoặc SUSPENDED")

    private String status;
} 