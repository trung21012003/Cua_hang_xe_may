package com.example.cua_hang_xe_may.dto;

public class ProductColorDTO {
    private Integer id;
    private Integer versionID;
    private String color;
    private String photo;
    private Double price;
    private String value;
    private Integer quantity;

    private String version;
    private String engieType;
    private String fuelConsumption;
    private String productName;

    public String getProductName() {
        return productName;
    }

    public void setProductName(String productName) {
        this.productName = productName;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getEngieType() {
        return engieType;
    }

    public void setEngieType(String engieType) {
        this.engieType = engieType;
    }

    public String getFuelConsumption() {
        return fuelConsumption;
    }

    public void setFuelConsumption(String fuelConsumption) {
        this.fuelConsumption = fuelConsumption;
    }

    public ProductColorDTO(Integer id, Integer versionID, String color, String photo, Double price, String value, Integer quantity) {
        this.id = id;
        this.versionID = versionID;
        this.color = color;
        this.photo = photo;
        this.price = price;
        this.value = value;
        this.quantity = quantity;
    }

    public ProductColorDTO() {
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Integer getVersionID() {
        return versionID;
    }

    public void setVersionID(Integer versionID) {
        this.versionID = versionID;
    }

    public String getColor() {
        return color;
    }

    public void setColor(String color) {
        this.color = color;
    }

    public String getPhoto() {
        return photo;
    }

    public void setPhoto(String photo) {
        this.photo = photo;
    }

    public Double getPrice() {
        return price;
    }

    public void setPrice(Double price) {
        this.price = price;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public Integer getQuantity() {
        return quantity;
    }

    public void setQuantity(Integer quantity) {
        this.quantity = quantity;
    }
}
