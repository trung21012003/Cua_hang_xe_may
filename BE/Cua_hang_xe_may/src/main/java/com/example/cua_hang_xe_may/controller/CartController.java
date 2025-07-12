package com.example.cua_hang_xe_may.controller;


import com.example.cua_hang_xe_may.dto.AccountDTO;
import com.example.cua_hang_xe_may.dto.CartDTO;
import com.example.cua_hang_xe_may.dto.CartResponseDTO;
import com.example.cua_hang_xe_may.dto.ProductColorDTO;
import com.example.cua_hang_xe_may.entities.Cart;
import com.example.cua_hang_xe_may.entities.Productcolor;
import com.example.cua_hang_xe_may.service.AccountService;
import com.example.cua_hang_xe_may.service.CartService;
import com.example.cua_hang_xe_may.service.ProductService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/cart")
public class CartController {

    @Autowired
    private CartService cartService;

    @Autowired
    private AccountService accountService;

    @GetMapping
    public ResponseEntity<List<ProductColorDTO>> getCart(Principal principal) {
        AccountDTO user = accountService.getAccountByUsername(principal.getName());
        List<ProductColorDTO> cartItems = cartService.findByUser(user);
        return ResponseEntity.ok(cartItems);
    }

    @PostMapping("/add")
    public ResponseEntity<?> addToCart(@RequestBody ProductColorDTO request, Principal principal) {
        if (principal == null) return ResponseEntity.status(401).body("Chưa đăng nhập");
        AccountDTO user = accountService.getAccountByUsername(principal.getName());
        cartService.addToCart(user, request);
        return ResponseEntity.ok("Thêm vào giỏ hàng thành công");
    }

    @PostMapping("/update")
    public String updateQuantity(@RequestParam int productColorId, @RequestParam int quantity, Principal principal) {
        AccountDTO user = accountService.getAccountByUsername(principal.getName());
        cartService.updateCartItem(user, productColorId, quantity);
        return "Cập nhật số lượng thành công";
    }

    @DeleteMapping("/remove")
    public String removeFromCart(@RequestParam Integer productColorId, Principal principal) {
        AccountDTO user = accountService.getAccountByUsername(principal.getName());
        cartService.removeFromCart(user, productColorId);
        return "Đã xóa sản phẩm khỏi giỏ hàng";
    }

    @GetMapping("/total")
    public CartResponseDTO calculateTotal(Principal principal) {
        AccountDTO user = accountService.getAccountByUsername(principal.getName());
        List<ProductColorDTO> cartItems = cartService.findByUser(user);

        double total = cartItems.stream()
                .mapToDouble(item -> item.getPrice() * item.getQuantity())
                .sum();

        return new CartResponseDTO(total);
    }
}


