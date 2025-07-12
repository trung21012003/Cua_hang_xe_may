package com.example.cua_hang_xe_may.repositories;

import com.example.cua_hang_xe_may.entities.Product;
import com.example.cua_hang_xe_may.entities.Productversion;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductRepository extends JpaRepository<Product, Integer> {

}