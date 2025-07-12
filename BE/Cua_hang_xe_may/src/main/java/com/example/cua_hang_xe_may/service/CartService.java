package com.example.cua_hang_xe_may.service;

import com.example.cua_hang_xe_may.dto.AccountDTO;
import com.example.cua_hang_xe_may.dto.ProductColorDTO;

import java.util.List;

public interface CartService {
    List<ProductColorDTO> findByUser(AccountDTO accountDTO);
    void addToCart(AccountDTO accountDTO, ProductColorDTO request);
    void updateCartItem(AccountDTO accountDTO, int productColorId, int quantity);
    void removeFromCart(AccountDTO accountDTO, int productColorId);
}
