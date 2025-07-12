package com.example.cua_hang_xe_may.dto;

import jakarta.validation.constraints.*;

public class CreateCommentRequest {
    @NotNull(message = "Product ID không được để trống")
    @Positive(message = "Product ID phải là số dương")
    private Integer productId;
    
    @NotBlank(message = "Nội dung bình luận không được để trống")
    @Size(min = 5, max = 500, message = "Nội dung bình luận phải có độ dài từ 5 đến 500 ký tự")
    private String content;
    
    @NotNull(message = "Đánh giá không được để trống")
    @Min(value = 1, message = "Đánh giá phải từ 1 đến 5 sao")
    @Max(value = 5, message = "Đánh giá phải từ 1 đến 5 sao")
    private Integer rating;

    public CreateCommentRequest() {
    }

    public CreateCommentRequest(Integer productId, String content, Integer rating) {
        this.productId = productId;
        this.content = content;
        this.rating = rating;
    }

    public Integer getProductId() {
        return productId;
    }

    public void setProductId(Integer productId) {
        this.productId = productId;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public Integer getRating() {
        return rating;
    }

    public void setRating(Integer rating) {
        this.rating = rating;
    }
} 