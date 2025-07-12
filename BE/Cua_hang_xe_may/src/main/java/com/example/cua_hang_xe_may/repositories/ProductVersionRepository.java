package com.example.cua_hang_xe_may.repositories;

import com.example.cua_hang_xe_may.entities.Productversion;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ProductVersionRepository extends JpaRepository <Productversion ,Integer>{
    List<Productversion> findAllByProductId(Integer productId);
}
