package com.example.cua_hang_xe_may.repositories;

import com.example.cua_hang_xe_may.entities.Productcolor;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ProductColorRepository extends JpaRepository<Productcolor,Integer> {
    
    // Tìm tất cả ProductColor theo Product ID
    @Query("SELECT pc FROM Productcolor pc WHERE pc.versionID.product.id = :productId")
    List<Productcolor> findByVersionID_Product_Id(@Param("productId") Integer productId);
}
