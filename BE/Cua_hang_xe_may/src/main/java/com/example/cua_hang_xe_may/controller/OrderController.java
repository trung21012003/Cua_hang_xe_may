package com.example.cua_hang_xe_may.controller;

import com.example.cua_hang_xe_may.entities.Order;
import com.example.cua_hang_xe_may.entities.OrderDetail;
import com.example.cua_hang_xe_may.repositories.OrderRepository;
import com.example.cua_hang_xe_may.repositories.OrderDetailRepository;
import com.example.cua_hang_xe_may.security.RoleChecker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    @Autowired
    private OrderRepository orderRepository;

    @Autowired
    private OrderDetailRepository orderDetailRepository;
    
    @Autowired
    private RoleChecker roleChecker;

    /**
     * Get order by ID - Enhanced with proper authorization
     */
    @GetMapping("/{orderId}")
    public ResponseEntity<?> getOrderById(@PathVariable Integer orderId, Principal principal) {
        Optional<Order> orderOpt = orderRepository.findById(orderId);
        
        if (orderOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        Order order = orderOpt.get();
        
        // Check if user can access this order
        if (principal != null) {
            String currentUsername = principal.getName();
            String orderOwnerUsername = order.getUser().getUsername();
            
            // User can access their own order, or admin/manager can access any order
            if (!currentUsername.equals(orderOwnerUsername) && !roleChecker.isAdminOrManager()) {
                return ResponseEntity.status(403).body("Access denied");
            }
        } else {
            // For payment result page compatibility - still allow public access for now
            // In production, you might want to implement a secure token-based access
        }
        
        // Load order details
        List<OrderDetail> orderDetails = orderDetailRepository.findByOrder(order);
        order.setOrderDetails(orderDetails);
        
        return ResponseEntity.ok(order);
    }

    /**
     * Get orders for current user
     */
    @GetMapping
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'MANAGER')")
    public ResponseEntity<?> getUserOrders(Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(401).build();
        }
        
        String username = principal.getName();
        
        // If admin or manager, they might want to see all orders instead
        if (roleChecker.isAdminOrManager()) {
            return ResponseEntity.ok("Use /api/orders/admin/all for admin access");
        }
        
        // Get orders for current user
        // Note: You'll need to add this method to OrderRepository
        // List<Order> userOrders = orderRepository.findByUserUsernameOrderByOrderDateDesc(username);
        
        return ResponseEntity.status(501).body("User orders endpoint needs to be implemented");
    }

    // ============= ADMIN/MANAGER ENDPOINTS =============
    
    /**
     * Get all orders (Admin/Manager only)
     */
    @GetMapping("/admin/all")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<?> getAllOrders(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "orderDate") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDir) {
        
        try {
            Sort sort = sortDir.equalsIgnoreCase("desc") ? 
                    Sort.by(sortBy).descending() : Sort.by(sortBy).ascending();
            
            Pageable pageable = PageRequest.of(page, size, sort);
            Page<Order> orders = orderRepository.findAll(pageable);
            
            // Load order details for each order
            orders.forEach(order -> {
                List<OrderDetail> orderDetails = orderDetailRepository.findByOrder(order);
                order.setOrderDetails(orderDetails);
            });
            
            return ResponseEntity.ok(orders);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching orders: " + e.getMessage());
        }
    }
    
    /**
     * Update order status (Admin/Manager only)
     */
    @PutMapping("/admin/{orderId}/status")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<?> updateOrderStatus(
            @PathVariable Integer orderId,
            @RequestParam String status) {
        
        try {
            Optional<Order> orderOpt = orderRepository.findById(orderId);
            
            if (orderOpt.isEmpty()) {
                return ResponseEntity.notFound().build();
            }
            
            Order order = orderOpt.get();
            
            // Validate status
            if (!status.matches("PENDING|CONFIRMED|PROCESSING|SHIPPED|DELIVERED|CANCELLED")) {
                return ResponseEntity.badRequest()
                        .body("Invalid status. Valid statuses: PENDING, CONFIRMED, PROCESSING, SHIPPED, DELIVERED, CANCELLED");
            }
            
            order.setStatus(status);
            orderRepository.save(order);
            
            return ResponseEntity.ok("Order status updated successfully");
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error updating order status: " + e.getMessage());
        }
    }
    
    /**
     * Get orders by status (Admin/Manager only)
     */
    @GetMapping("/admin/status/{status}")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<?> getOrdersByStatus(
            @PathVariable String status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        
        try {
            Pageable pageable = PageRequest.of(page, size, Sort.by("orderDate").descending());
            // Note: You'll need to add this method to OrderRepository
            // Page<Order> orders = orderRepository.findByStatusOrderByOrderDateDesc(status, pageable);
            
            return ResponseEntity.status(501).body("Orders by status endpoint needs to be implemented in repository");
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching orders by status: " + e.getMessage());
        }
    }
}