package com.example.cua_hang_xe_may.controller;

import com.example.cua_hang_xe_may.dto.ApiResponse;
import com.example.cua_hang_xe_may.dto.CommentDTO;
import com.example.cua_hang_xe_may.dto.CreateCommentRequest;
import com.example.cua_hang_xe_may.entities.Account;
import com.example.cua_hang_xe_may.entities.Comment;
import com.example.cua_hang_xe_may.entities.OrderDetail;
import com.example.cua_hang_xe_may.repositories.AccountRepository;
import com.example.cua_hang_xe_may.repositories.CommentRepository;
import com.example.cua_hang_xe_may.repositories.OrderDetailRepository;
import com.example.cua_hang_xe_may.repositories.ProductColorRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/comments")
public class CommentController {

    @Autowired
    private CommentRepository commentRepository;

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private OrderDetailRepository orderDetailRepository;

    @Autowired
    private ProductColorRepository productColorRepository;

    // ============= PUBLIC ENDPOINTS =============
    
    // Lấy comments của sản phẩm (public access)
    @GetMapping("/public/product/{productId}")
    public ResponseEntity<List<CommentDTO>> getProductCommentsPublic(@PathVariable Integer productId) {
        List<Comment> comments = commentRepository.findByProductIdOrderByCreatedDesc(productId);
        
        List<CommentDTO> commentDTOs = comments.stream().map(comment -> {
            CommentDTO dto = new CommentDTO();
            dto.setId(comment.getId());
            dto.setProductId(comment.getProductId());
            dto.setContent(comment.getContent());
            dto.setRating(comment.getRating());
            dto.setCreated(comment.getCreated());
            dto.setUsername(comment.getAccount().getUsername());
            dto.setName(comment.getAccount().getName() != null ? comment.getAccount().getName() : comment.getAccount().getUsername());
            return dto;
        }).collect(Collectors.toList());

        return ResponseEntity.ok(commentDTOs);
    }

    // Lấy thống kê rating của sản phẩm (public access)
    @GetMapping("/public/product/{productId}/rating-stats")
    public ResponseEntity<Map<String, Object>> getProductRatingStatsPublic(@PathVariable Integer productId) {
        Map<String, Object> stats = new HashMap<>();
        
        // Rating trung bình
        Double avgRating = commentRepository.getAverageRatingByProductId(productId);
        stats.put("averageRating", avgRating != null ? Math.round(avgRating * 10.0) / 10.0 : 0.0);
        
        // Tổng số đánh giá
        List<Comment> allComments = commentRepository.findByProductIdOrderByCreatedDesc(productId);
        stats.put("totalReviews", allComments.size());
        
        // Phân bố rating
        List<Object[]> distribution = commentRepository.getRatingDistribution(productId);
        Map<Integer, Long> ratingCount = new HashMap<>();
        
        // Khởi tạo với 0 cho tất cả rating từ 1-5
        for (int i = 1; i <= 5; i++) {
            ratingCount.put(i, 0L);
        }
        
        // Cập nhật với dữ liệu thực
        for (Object[] row : distribution) {
            Integer rating = (Integer) row[0];
            Long count = (Long) row[1];
            ratingCount.put(rating, count);
        }
        
        stats.put("ratingDistribution", ratingCount);
        
        return ResponseEntity.ok(stats);
    }

    // ============= AUTHENTICATED ENDPOINTS =============
    
    // Lấy comments của sản phẩm (backward compatibility)
    @GetMapping("/product/{productId}")
    public ResponseEntity<List<CommentDTO>> getProductComments(@PathVariable Integer productId) {
        return getProductCommentsPublic(productId);
    }

    // Lấy thống kê rating của sản phẩm (backward compatibility)
    @GetMapping("/product/{productId}/rating-stats")
    public ResponseEntity<Map<String, Object>> getProductRatingStats(@PathVariable Integer productId) {
        return getProductRatingStatsPublic(productId);
    }

    // Kiểm tra user có thể đánh giá sản phẩm không
    @GetMapping("/can-review/product/{productId}")
    public ResponseEntity<Map<String, Boolean>> canUserReview(@PathVariable Integer productId, Principal principal) {
        Map<String, Boolean> result = new HashMap<>();
        
        if (principal == null) {
            result.put("canReview", false);
            result.put("hasPurchased", false);
            result.put("hasReviewed", false);
            return ResponseEntity.ok(result);
        }

        Optional<Account> accountOpt = accountRepository.findByUsername(principal.getName());
        if (accountOpt.isEmpty()) {
            result.put("canReview", false);
            result.put("hasPurchased", false);
            result.put("hasReviewed", false);
            return ResponseEntity.ok(result);
        }

        Account account = accountOpt.get();
        
        // Kiểm tra đã mua sản phẩm chưa (kiểm tra trong order details)
        boolean hasPurchased = orderDetailRepository.existsByOrderUserAndProductColorIdIn(
            account, 
            productColorRepository.findByVersionID_Product_Id(productId)
                .stream().map(pc -> pc.getId()).collect(Collectors.toList())
        );
        
        // Kiểm tra đã đánh giá chưa
        boolean hasReviewed = commentRepository.existsByAccountAndProductId(account, productId);
        
        result.put("hasPurchased", hasPurchased);
        result.put("hasReviewed", hasReviewed);
        result.put("canReview", hasPurchased && !hasReviewed);
        
        return ResponseEntity.ok(result);
    }

    // Tạo comment/đánh giá mới
    @PostMapping
    public ResponseEntity<ApiResponse> createComment(@Valid @RequestBody CreateCommentRequest request, Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(401).body(new ApiResponse("Vui lòng đăng nhập để đánh giá", false));
        }

        Optional<Account> accountOpt = accountRepository.findByUsername(principal.getName());
        if (accountOpt.isEmpty()) {
            return ResponseEntity.status(404).body(new ApiResponse("Không tìm thấy tài khoản", false));
        }

        Account account = accountOpt.get();

        // Validate rating
        if (request.getRating() < 1 || request.getRating() > 5) {
            return ResponseEntity.badRequest().body(new ApiResponse("Đánh giá phải từ 1 đến 5 sao", false));
        }

        // Validate content
        if (request.getContent() == null || request.getContent().trim().isEmpty()) {
            return ResponseEntity.badRequest().body(new ApiResponse("Nội dung đánh giá không được để trống", false));
        }

        // Kiểm tra đã mua sản phẩm chưa
        boolean hasPurchased = orderDetailRepository.existsByOrderUserAndProductColorIdIn(
            account,
            productColorRepository.findByVersionID_Product_Id(request.getProductId())
                .stream().map(pc -> pc.getId()).collect(Collectors.toList())
        );

        if (!hasPurchased) {
            return ResponseEntity.badRequest().body(new ApiResponse("Bạn chỉ có thể đánh giá sản phẩm đã mua", false));
        }

        // Kiểm tra đã đánh giá chưa
        boolean hasReviewed = commentRepository.existsByAccountAndProductId(account, request.getProductId());
        if (hasReviewed) {
            return ResponseEntity.badRequest().body(new ApiResponse("Bạn đã đánh giá sản phẩm này rồi", false));
        }

        // Tạo comment mới
        Comment comment = new Comment();
        comment.setAccount(account);
        comment.setProductId(request.getProductId());
        comment.setContent(request.getContent().trim());
        comment.setRating(request.getRating());
        comment.setCreated(Instant.now());

        commentRepository.save(comment);

        return ResponseEntity.ok(new ApiResponse("Đánh giá của bạn đã được thêm thành công", true));
    }
} 