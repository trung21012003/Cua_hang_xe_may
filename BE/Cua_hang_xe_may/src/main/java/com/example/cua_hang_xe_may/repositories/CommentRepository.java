package com.example.cua_hang_xe_may.repositories;

import com.example.cua_hang_xe_may.entities.Account;
import com.example.cua_hang_xe_may.entities.Comment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CommentRepository extends JpaRepository<Comment, Integer> {
    
    // Lấy tất cả comments của một sản phẩm, sắp xếp theo ngày tạo giảm dần
    List<Comment> findByProductIdOrderByCreatedDesc(Integer productId);
    
    // Kiểm tra xem user đã comment cho sản phẩm này chưa
    boolean existsByAccountAndProductId(Account account, Integer productId);
    
    // Lấy comment của user cho sản phẩm cụ thể
    Comment findByAccountAndProductId(Account account, Integer productId);
    
    // Tính rating trung bình của sản phẩm
    @Query("SELECT AVG(c.rating) FROM Comment c WHERE c.productId = :productId")
    Double getAverageRatingByProductId(@Param("productId") Integer productId);
    
    // Đếm số lượng đánh giá theo từng số sao
    @Query("SELECT c.rating, COUNT(c) FROM Comment c WHERE c.productId = :productId GROUP BY c.rating ORDER BY c.rating DESC")
    List<Object[]> getRatingDistribution(@Param("productId") Integer productId);
} 