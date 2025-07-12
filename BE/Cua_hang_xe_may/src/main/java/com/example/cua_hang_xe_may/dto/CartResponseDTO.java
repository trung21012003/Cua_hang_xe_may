package com.example.cua_hang_xe_may.dto;

public class CartResponseDTO {
    private double total;

    public double getTotal() {
        return total;
    }

    public void setTotal(double total) {
        this.total = total;
    }


    public CartResponseDTO(double total) {
        this.total = total;

    }
}

