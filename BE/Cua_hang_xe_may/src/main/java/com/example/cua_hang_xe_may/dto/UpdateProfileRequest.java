package com.example.cua_hang_xe_may.dto;

import jakarta.validation.constraints.*;
import java.time.Instant;

public class UpdateProfileRequest {
    @Size(min = 2, max = 100, message = "Tên phải có độ dài từ 2 đến 100 ký tự")
    private String name;
    
    @Pattern(regexp = "^$|^[0-9]{10,11}$", message = "Số điện thoại phải có 10-11 chữ số hoặc để trống")
    private String phone;
    
    @Size(max = 255, message = "Địa chỉ không được vượt quá 255 ký tự")
    private String address;
    
    @Past(message = "Ngày sinh phải là ngày trong quá khứ")
    private Instant dob;

    public UpdateProfileRequest() {
    }

    public UpdateProfileRequest(String name, String phone, String address, Instant dob) {
        this.name = name;
        this.phone = phone;
        this.address = address;
        this.dob = dob;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public Instant getDob() {
        return dob;
    }

    public void setDob(Instant dob) {
        this.dob = dob;
    }
} 