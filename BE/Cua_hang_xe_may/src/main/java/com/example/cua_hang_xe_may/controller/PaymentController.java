package com.example.cua_hang_xe_may.controller;

import com.example.cua_hang_xe_may.dto.AccountDTO;
import com.example.cua_hang_xe_may.dto.ApiResponse;
import com.example.cua_hang_xe_may.dto.PaymentRequestDTO;
import com.example.cua_hang_xe_may.dto.ProductColorDTO;
import com.example.cua_hang_xe_may.entities.Order;
import com.example.cua_hang_xe_may.repositories.OrderRepository;
import com.example.cua_hang_xe_may.service.AccountService;
import com.example.cua_hang_xe_may.service.CartService;
import com.example.cua_hang_xe_may.service.PaymentService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import java.security.Principal;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/payment")
public class PaymentController {

    @Autowired
    private PaymentService paymentService;

    @Autowired
    private AccountService accountService;

    @Autowired
    private CartService cartService;

    @Autowired
    private OrderRepository orderRepository;

    /**
     * Create a payment for the current user's cart
     */
    @PostMapping("/create")
    public ResponseEntity<?> createPayment(@Valid @RequestBody PaymentRequestDTO request, Principal principal, HttpServletRequest httpRequest) {
        if (principal == null) {
            return ResponseEntity.status(401).body(new ApiResponse("Chưa đăng nhập", false));
        }

        try {
            // Get current user
            AccountDTO user = accountService.getAccountByUsername(principal.getName());

            // Create order from cart
            Order order = paymentService.createOrderFromCart(
                    user,
                    request.getShippingAddress(),
                    request.getShippingPhone(),
                    request.getShippingName()
            );

            // Get client IP address
            String ipAddress = httpRequest.getRemoteAddr();

            // Create payment URL
            String paymentUrl = paymentService.createPaymentUrl(order, ipAddress);

            // Return payment URL
            Map<String, String> response = new HashMap<>();
            response.put("paymentUrl", paymentUrl);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new ApiResponse(e.getMessage(), false));
        }
    }

    /**
     * Handle VNPay payment return
     */
    @GetMapping("/vnpay-return")
    public RedirectView paymentReturn(HttpServletRequest request) {
        // Get all parameters from the request
        Map<String, String> vnpParams = new HashMap<>();
        Enumeration<String> paramNames = request.getParameterNames();

        while (paramNames.hasMoreElements()) {
            String paramName = paramNames.nextElement();
            String paramValue = request.getParameter(paramName);
            vnpParams.put(paramName, paramValue);
        }

        // Process payment response
        boolean paymentSuccess = paymentService.processPaymentResponse(vnpParams);

        // Redirect to frontend with payment result
        String frontendUrl = "http://localhost:5173/payment-result";
        String redirectUrl = frontendUrl + "?success=" + paymentSuccess;

        if (paymentSuccess) {
            // If payment is successful, get the order ID
            String orderId = vnpParams.get("vnp_TxnRef");
            redirectUrl += "&orderId=" + orderId;

            try {
                // Find the order to get the user
                Order order = orderRepository.findById(Integer.parseInt(orderId)).orElse(null);
                if (order != null) {
                    // Convert Account to AccountDTO
                    AccountDTO accountDTO = new AccountDTO();
                    accountDTO.setId(order.getUser().getId());

                    // Get cart items
                    List<ProductColorDTO> cartItems = cartService.findByUser(accountDTO);

                    // Remove each item from cart
                    for (ProductColorDTO item : cartItems) {
                        cartService.removeFromCart(accountDTO, item.getId());
                    }
                }
            } catch (Exception e) {
                // Log error but continue with redirect
                System.err.println("Failed to clear cart: " + e.getMessage());
            }
        }

        return new RedirectView(redirectUrl);
    }
}
