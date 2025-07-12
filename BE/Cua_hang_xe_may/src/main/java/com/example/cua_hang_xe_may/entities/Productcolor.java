package com.example.cua_hang_xe_may.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

@Getter
@Setter
@Entity
@Table(name = "productcolor")
public class Productcolor {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    @JoinColumn(name = "versionID", nullable = false)
    private Productversion versionID;

    @Column(name = "color", nullable = false, length = 50)
    private String color;

    @Column(name = "photo", nullable = false, length = 500)
    private String photo;

    @Column(name = "price", nullable = false)
    private Double price;

    @Column(name = "value", nullable = false, length = 50)
    private String value;

    @Column(name = "quantity")
    private Integer quantity;

}