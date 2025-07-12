package com.example.cua_hang_xe_may.entities;

import jakarta.persistence.*;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "products")
public class Product {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @Column(name = "avatar", length = 200)
    private String avatar;

    @Column(name = "name", length = 200)
    private String name;

    @Column(name = "description", length = 200)
    private String description;

    @Column(name = "price")
    private Double price;

    @Column(name = "weight", nullable = false, length = 250)
    private String weight;

    @Column(name = "size", nullable = false, length = 250)
    private String size;

    @Column(name = "petrolCapacity", nullable = false, length = 250)
    private String petrolCapacity;

    @Column(name = "saddleHeight", nullable = false, length = 250)
    private String saddleHeight;

    @Column(name = "wheelSize", nullable = false, length = 250)
    private String wheelSize;

    @Column(name = "beforeFork", nullable = false, length = 250)
    private String beforeFork;

    @Column(name = "afterFork", nullable = false, length = 250)
    private String afterFork;

    @Column(name = "maxiumCapacity", nullable = false, length = 250)
    private String maxiumCapacity;

    @Column(name = "oilCapacity", nullable = false, length = 250)
    private String oilCapacity;

    @Column(name = "fuelConsumption", nullable = false, length = 250)
    private String fuelConsumption;

    @Column(name = "cylinderCapacity", nullable = false, length = 250)
    private String cylinderCapacity;

    @Column(name = "maxiumMoment", nullable = false, length = 250)
    private String maxiumMoment;

    @Column(name = "compressionRatio", nullable = false, length = 250)
    private String compressionRatio;

    @Column(name = "engieType", nullable = false, length = 250)
    private String engieType;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JoinColumn(name = "brandId", nullable = false)
    private Brand brand;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JoinColumn(name = "motolineId", nullable = false)
    private Motoline motoline;

    @OneToMany(mappedBy = "product", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private List<Productversion> productVersions = new ArrayList<>();

    public Motoline getMotoline() {
        return motoline;
    }

    public void setMotoline(Motoline motoline) {
        this.motoline = motoline;
    }

    public Brand getBrand() {
        return brand;
    }

    public void setBrand(Brand brand) {
        this.brand = brand;
    }

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

}