package com.example.cua_hang_xe_may.dto;

public class CartDTO {
    private int id;
    private int user_id;
    private int product_color_id;
    private Integer quantity;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getUser_id() {
        return user_id;
    }

    public void setUser_id(int user_id) {
        this.user_id = user_id;
    }

    public int getProduct_color_id() {
        return product_color_id;
    }

    public void setProduct_color_id(int product_color_id) {
        this.product_color_id = product_color_id;
    }

    public Integer getQuantity() {
        return quantity;
    }

    public void setQuantity(Integer quantity) {
        this.quantity = quantity;
    }

    public CartDTO(int id, int user_id, int product_color_id, Integer quantity) {
        this.id = id;
        this.user_id = user_id;
        this.product_color_id = product_color_id;
        this.quantity = quantity;
    }
}
