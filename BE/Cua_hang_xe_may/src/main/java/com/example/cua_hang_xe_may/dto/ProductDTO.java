package com.example.cua_hang_xe_may.dto;

import jakarta.validation.constraints.*;
import jakarta.validation.Valid;
import java.util.List;

public class ProductDTO {
    private Integer id;
    
    @Size(max = 255, message = "Avatar URL không được vượt quá 255 ký tự")
    private String avatar;
    
    @NotBlank(message = "Tên sản phẩm không được để trống")
    @Size(min = 2, max = 200, message = "Tên sản phẩm phải có độ dài từ 2 đến 200 ký tự")
    private String name;
    
    @Size(max = 1000, message = "Mô tả không được vượt quá 1000 ký tự")
    private String description;
    
    @NotNull(message = "Giá không được để trống")
    @DecimalMin(value = "0.0", inclusive = false, message = "Giá phải lớn hơn 0")
    @DecimalMax(value = "999999999.99", message = "Giá không được vượt quá 999,999,999.99")
    private Double price;
    private String weight;
    private String size;
    private String petrolCapacity;
    private String saddleHeight;
    private String wheelSize;
    private String beforeFork;
    private String afterFork;
    private String maxiumCapacity;
    private String oilCapacity;
    private String fuelConsumption;
    private String cylinderCapacity;
    private String maxiumMoment;
    private String compressionRatio;
    private String engieType;
    private String brandName; // Chỉ lấy tên của Brand
    private String motolineName; // Chỉ lấy tên của Motoline
    
    @Valid
    private BrandDTO brand;
    
    @Valid
    private List<ProductVersionDTO> versionColors;
    
    @Min(value = 0, message = "Số lượng tồn kho không được âm")
    private Integer totalStock; // Tổng số lượng tồn kho
    
    @Pattern(regexp = "^(ACTIVE|INACTIVE|OUT_OF_STOCK)$", message = "Status phải là ACTIVE, INACTIVE hoặc OUT_OF_STOCK")

    private String status; // Trạng thái sản phẩm

    public List<ProductVersionDTO> getVersionColors() {
        return versionColors;
    }

    public void setVersionColors(List<ProductVersionDTO> versionColors) {
        this.versionColors = versionColors;
    }

    public BrandDTO getBrand() {
        return brand;
    }

    public void setBrand(BrandDTO brand) {
        this.brand = brand;
    }

    public Integer getTotalStock() {
        return totalStock;
    }

    public void setTotalStock(Integer totalStock) {
        this.totalStock = totalStock;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    // Getters và Setters
    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getAvatar() {
        return avatar;
    }

    public void setAvatar(String avatar) {
        this.avatar = avatar;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Double getPrice() {
        return price;
    }

    public void setPrice(Double price) {
        this.price = price;
    }

    public String getWeight() {
        return weight;
    }

    public void setWeight(String weight) {
        this.weight = weight;
    }

    public String getSize() {
        return size;
    }

    public void setSize(String size) {
        this.size = size;
    }

    public String getPetrolCapacity() {
        return petrolCapacity;
    }

    public void setPetrolCapacity(String petrolCapacity) {
        this.petrolCapacity = petrolCapacity;
    }

    public String getSaddleHeight() {
        return saddleHeight;
    }

    public void setSaddleHeight(String saddleHeight) {
        this.saddleHeight = saddleHeight;
    }

    public String getWheelSize() {
        return wheelSize;
    }

    public void setWheelSize(String wheelSize) {
        this.wheelSize = wheelSize;
    }

    public String getBeforeFork() {
        return beforeFork;
    }

    public void setBeforeFork(String beforeFork) {
        this.beforeFork = beforeFork;
    }

    public String getAfterFork() {
        return afterFork;
    }

    public void setAfterFork(String afterFork) {
        this.afterFork = afterFork;
    }

    public String getMaxiumCapacity() {
        return maxiumCapacity;
    }

    public void setMaxiumCapacity(String maxiumCapacity) {
        this.maxiumCapacity = maxiumCapacity;
    }

    public String getOilCapacity() {
        return oilCapacity;
    }

    public void setOilCapacity(String oilCapacity) {
        this.oilCapacity = oilCapacity;
    }

    public String getFuelConsumption() {
        return fuelConsumption;
    }

    public void setFuelConsumption(String fuelConsumption) {
        this.fuelConsumption = fuelConsumption;
    }

    public String getCylinderCapacity() {
        return cylinderCapacity;
    }

    public void setCylinderCapacity(String cylinderCapacity) {
        this.cylinderCapacity = cylinderCapacity;
    }

    public String getMaxiumMoment() {
        return maxiumMoment;
    }

    public void setMaxiumMoment(String maxiumMoment) {
        this.maxiumMoment = maxiumMoment;
    }

    public String getCompressionRatio() {
        return compressionRatio;
    }

    public void setCompressionRatio(String compressionRatio) {
        this.compressionRatio = compressionRatio;
    }

    public String getEngieType() {
        return engieType;
    }

    public void setEngieType(String engieType) {
        this.engieType = engieType;
    }

    public String getBrandName() {
        return brandName;
    }

    public void setBrandName(String brandName) {
        this.brandName = brandName;
    }

    public String getMotolineName() {
        return motolineName;
    }

    public void setMotolineName(String motolineName) {
        this.motolineName = motolineName;
    }
}