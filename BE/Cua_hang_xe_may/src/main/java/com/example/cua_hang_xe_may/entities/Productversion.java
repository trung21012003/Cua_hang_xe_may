package com.example.cua_hang_xe_may.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Entity
@Table(name = "productversions")
public class Productversion {
    @Id
    @Column(name = "id", nullable = false)
    private Integer id;

    @Column(name = "versionname", nullable = false, length = 250)
    private String versionname;

    @Column(name = "price", nullable = false)
    private Double price;

    @ManyToOne
    @JoinColumn(name = "productid", nullable = false)
    private Product product;

    @OneToMany(mappedBy = "versionID", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Productcolor> colors;

}