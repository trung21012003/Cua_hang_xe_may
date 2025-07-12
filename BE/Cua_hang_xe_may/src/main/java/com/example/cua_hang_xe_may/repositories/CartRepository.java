package com.example.cua_hang_xe_may.repositories;

import com.example.cua_hang_xe_may.dto.AccountDTO;
import com.example.cua_hang_xe_may.entities.Account;
import com.example.cua_hang_xe_may.entities.Cart;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;


public interface CartRepository extends JpaRepository<Cart, Integer> {
    List<Cart> findByUserAndProductColorId(Account user, Integer productColorId);
    List<Cart> findByUser(Account user);
    List<Cart> findByProductColorId(Integer productColorId);
}
