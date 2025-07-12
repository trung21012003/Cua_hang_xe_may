package com.example.cua_hang_xe_may.repositories;

import com.example.cua_hang_xe_may.entities.Account;
import com.example.cua_hang_xe_may.entities.Order;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OrderRepository extends JpaRepository<Order, Integer> {
    List<Order> findByUser(Account user);
    List<Order> findByUserOrderByOrderDateDesc(Account user);
    Optional<Order> findByTransactionId(String transactionId);
}