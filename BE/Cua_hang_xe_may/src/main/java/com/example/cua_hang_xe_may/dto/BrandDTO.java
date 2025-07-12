package com.example.cua_hang_xe_may.dto;

import jakarta.validation.constraints.*;

public class BrandDTO {
    private Integer id;
    
    @NotBlank(message = "Tên thương hiệu không được để trống")
    @Size(min = 2, max = 100, message = "Tên thương hiệu phải có độ dài từ 2 đến 100 ký tự")
    private String name;
    
    @Size(max = 255, message = "URL ảnh không được vượt quá 255 ký tự")
    private String photo;
    
    @Size(max = 500, message = "Mô tả không được vượt quá 500 ký tự")
    private String description;

    public BrandDTO() {
    }

    public BrandDTO(Integer id, String name, String photo, String description) {
        this.id = id;
        this.name = name;
        this.photo = photo;
        this.description = description;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPhoto() {
        return photo;
    }

    public void setPhoto(String photo) {
        this.photo = photo;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

}
