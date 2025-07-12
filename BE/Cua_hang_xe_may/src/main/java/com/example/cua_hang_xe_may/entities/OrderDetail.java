package com.example.cua_hang_xe_may.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "order_details")
public class OrderDetail {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "order_id", nullable = false)
    @JsonIgnore
    private Order order;

    @Column(name = "product_color_id", nullable = false)
    private Integer productColorId;

    @Column(name = "quantity", nullable = false)
    private Integer quantity;

    @Column(name = "price", nullable = false)
    private Double price;

    @Column(name = "product_name", length = 200)
    private String productName;

    @Column(name = "product_version", length = 100)
    private String productVersion;

    @Column(name = "product_color", length = 50)
    private String productColor;

    @Column(name = "product_image", length = 500)
    private String productImage;
}
