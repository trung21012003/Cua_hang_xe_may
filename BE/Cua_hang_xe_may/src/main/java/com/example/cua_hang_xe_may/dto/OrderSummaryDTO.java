package com.example.cua_hang_xe_may.dto;

import java.time.Instant;

public class OrderSummaryDTO {
    private Integer id;
    private String orderId;
    private Instant orderDate;
    private Double totalAmount;
    private String status;
    private String paymentMethod;
    private String transactionId;
    private Integer totalItems;
    private String mainProductName;

    public OrderSummaryDTO() {
    }

    public OrderSummaryDTO(Integer id, String orderId, Instant orderDate, Double totalAmount, 
                          String status, String paymentMethod, String transactionId, 
                          Integer totalItems, String mainProductName) {
        this.id = id;
        this.orderId = orderId;
        this.orderDate = orderDate;
        this.totalAmount = totalAmount;
        this.status = status;
        this.paymentMethod = paymentMethod;
        this.transactionId = transactionId;
        this.totalItems = totalItems;
        this.mainProductName = mainProductName;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getOrderId() {
        return orderId;
    }

    public void setOrderId(String orderId) {
        this.orderId = orderId;
    }

    public Instant getOrderDate() {
        return orderDate;
    }

    public void setOrderDate(Instant orderDate) {
        this.orderDate = orderDate;
    }

    public Double getTotalAmount() {
        return totalAmount;
    }

    public void setTotalAmount(Double totalAmount) {
        this.totalAmount = totalAmount;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getPaymentMethod() {
        return paymentMethod;
    }

    public void setPaymentMethod(String paymentMethod) {
        this.paymentMethod = paymentMethod;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public Integer getTotalItems() {
        return totalItems;
    }

    public void setTotalItems(Integer totalItems) {
        this.totalItems = totalItems;
    }

    public String getMainProductName() {
        return mainProductName;
    }

    public void setMainProductName(String mainProductName) {
        this.mainProductName = mainProductName;
    }
} 