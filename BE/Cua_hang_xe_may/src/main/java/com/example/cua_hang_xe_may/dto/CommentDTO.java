package com.example.cua_hang_xe_may.dto;

import java.time.Instant;

public class CommentDTO {
    private Integer id;
    private Integer productId;
    private String content;
    private Integer rating;
    private Instant created;
    
    // Thông tin người dùng
    private String username;
    private String name;
    
    public CommentDTO() {
    }

    public CommentDTO(Integer id, Integer productId, String content, Integer rating, 
                     Instant created, String username, String name) {
        this.id = id;
        this.productId = productId;
        this.content = content;
        this.rating = rating;
        this.created = created;
        this.username = username;
        this.name = name;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
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

    public Instant getCreated() {
        return created;
    }

    public void setCreated(Instant created) {
        this.created = created;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
} 