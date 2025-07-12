package com.example.cua_hang_xe_may.dto;

import lombok.Getter;
import lombok.Setter;
import jakarta.validation.constraints.*;

@Getter
@Setter
public class PaymentRequestDTO {
    @NotBlank(message = "Địa chỉ giao hàng không được để trống")
    @Size(max = 255, message = "Địa chỉ giao hàng không được vượt quá 255 ký tự")
    private String shippingAddress;
    
    @NotBlank(message = "Số điện thoại giao hàng không được để trống")
    @Pattern(regexp = "^[0-9\\-\\s\\+\\.\\(\\)]{10,15}$", message = "Số điện thoại không hợp lệ")
    private String shippingPhone;
    
    @NotBlank(message = "Tên người nhận không được để trống")
    @Size(min = 2, max = 100, message = "Tên người nhận phải có độ dài từ 2 đến 100 ký tự")
    private String shippingName;
}