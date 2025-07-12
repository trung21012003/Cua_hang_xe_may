package com.example.cua_hang_xe_may.dto;

import java.util.List;

public class ProductVersionDTO {
    private Integer id;
    private Integer productID;
    private String versionName;
    private Double price;
    private List<ProductColorDTO> colors;

    public List<ProductColorDTO> getColors() {
        return colors;
    }

    public void setColors(List<ProductColorDTO> colors) {
        this.colors = colors;
    }

    public ProductVersionDTO(Integer id, Integer productID, String versionName, Double price) {
        this.id = id;
        this.productID = productID;
        this.versionName = versionName;
        this.price = price;
    }

    public ProductVersionDTO() {
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Integer getProductID() {
        return productID;
    }

    public void setProductID(Integer productID) {
        this.productID = productID;
    }

    public String getVersionName() {
        return versionName;
    }

    public void setVersionName(String versionName) {
        this.versionName = versionName;
    }

    public Double getPrice() {
        return price;
    }

    public void setPrice(Double price) {
        this.price = price;
    }
}
