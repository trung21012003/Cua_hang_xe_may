package com.example.cua_hang_xe_may.repositories;

import com.example.cua_hang_xe_may.entities.Account;
import com.example.cua_hang_xe_may.entities.Order;
import com.example.cua_hang_xe_may.entities.OrderDetail;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface OrderDetailRepository extends JpaRepository<OrderDetail, Integer> {
    List<OrderDetail> findByOrder(Order order);
    
    // Kiểm tra user đã mua sản phẩm (thông qua productColorId)
    @Query("SELECT CASE WHEN COUNT(od) > 0 THEN true ELSE false END FROM OrderDetail od " +
           "WHERE od.order.user = :user AND od.productColorId IN :productColorIds " +
           "AND od.order.status IN ('paid', 'completed', 'success')")
    boolean existsByOrderUserAndProductColorIdIn(@Param("user") Account user, 
                                                @Param("productColorIds") List<Integer> productColorIds);
}