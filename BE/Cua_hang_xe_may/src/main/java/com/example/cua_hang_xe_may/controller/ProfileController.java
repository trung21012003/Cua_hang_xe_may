package com.example.cua_hang_xe_may.controller;

import com.example.cua_hang_xe_may.dto.AccountDTO;
import com.example.cua_hang_xe_may.dto.ApiResponse;
import com.example.cua_hang_xe_may.dto.OrderSummaryDTO;
import com.example.cua_hang_xe_may.dto.UpdateProfileRequest;
import com.example.cua_hang_xe_may.entities.Account;
import com.example.cua_hang_xe_may.entities.Order;
import com.example.cua_hang_xe_may.entities.OrderDetail;
import com.example.cua_hang_xe_may.repositories.AccountRepository;
import com.example.cua_hang_xe_may.repositories.OrderDetailRepository;
import com.example.cua_hang_xe_may.repositories.OrderRepository;
import com.example.cua_hang_xe_may.service.AccountService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    @Autowired
    private AccountService accountService;

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private OrderRepository orderRepository;

    @Autowired
    private OrderDetailRepository orderDetailRepository;

    @GetMapping
    public ResponseEntity<AccountDTO> getProfile(Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(401).build();
        }
        
        AccountDTO profile = accountService.getAccountByUsername(principal.getName());
        return ResponseEntity.ok(profile);
    }

    @GetMapping("/orders")
    public ResponseEntity<List<OrderSummaryDTO>> getOrderHistory(Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(401).build();
        }

        try {
            Optional<Account> accountOpt = accountRepository.findByUsername(principal.getName());
            if (accountOpt.isEmpty()) {
                return ResponseEntity.status(404).build();
            }

            Account account = accountOpt.get();
            List<Order> orders = orderRepository.findByUserOrderByOrderDateDesc(account);

            List<OrderSummaryDTO> orderSummaries = orders.stream().map(order -> {
                // Load order details to get item count and main product
                List<OrderDetail> orderDetails = orderDetailRepository.findByOrder(order);
                
                int totalItems = orderDetails.stream().mapToInt(OrderDetail::getQuantity).sum();
                String mainProductName = orderDetails.isEmpty() ? "Không có sản phẩm" : 
                    orderDetails.get(0).getProductName();

                OrderSummaryDTO dto = new OrderSummaryDTO();
                dto.setId(order.getId());
                dto.setOrderId("HD-" + String.format("%06d", order.getId()));
                dto.setOrderDate(order.getOrderDate());
                dto.setTotalAmount(order.getTotalAmount());
                dto.setStatus(order.getStatus());
                dto.setPaymentMethod(order.getPaymentMethod());
                dto.setTransactionId(order.getTransactionId());
                dto.setTotalItems(totalItems);
                dto.setMainProductName(mainProductName);

                return dto;
            }).collect(Collectors.toList());

            return ResponseEntity.ok(orderSummaries);
        } catch (Exception e) {
            return ResponseEntity.status(500).build();
        }
    }

    @PutMapping
    public ResponseEntity<ApiResponse> updateProfile(@Valid @RequestBody UpdateProfileRequest request, Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(401).body(new ApiResponse("Chưa đăng nhập", false));
        }

        try {
            Optional<Account> accountOpt = accountRepository.findByUsername(principal.getName());
            if (accountOpt.isEmpty()) {
                return ResponseEntity.status(404).body(new ApiResponse("Không tìm thấy tài khoản", false));
            }

            Account account = accountOpt.get();
            
            // Cập nhật thông tin
            if (request.getName() != null && !request.getName().isEmpty()) {
                account.setName(request.getName());
            }
            if (request.getPhone() != null && !request.getPhone().isEmpty()) {
                account.setPhone(request.getPhone());
            }
            if (request.getAddress() != null && !request.getAddress().isEmpty()) {
                account.setAddress(request.getAddress());
            }
            if (request.getDob() != null) {
                account.setDob(request.getDob());
            }

            accountRepository.save(account);

            return ResponseEntity.ok(new ApiResponse("Cập nhật thông tin thành công", true));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(new ApiResponse("Có lỗi xảy ra khi cập nhật thông tin", false));
        }
    }
} 