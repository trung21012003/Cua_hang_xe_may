package com.example.cua_hang_xe_may.service;

import com.example.cua_hang_xe_may.dto.AccountDTO;
import com.example.cua_hang_xe_may.dto.ProductColorDTO;
import com.example.cua_hang_xe_may.entities.Account;
import com.example.cua_hang_xe_may.entities.Cart;
import com.example.cua_hang_xe_may.entities.Productcolor;
import com.example.cua_hang_xe_may.repositories.CartRepository;
import com.example.cua_hang_xe_may.repositories.ProductColorRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
public class CartServiceImpl implements CartService {

    @Autowired
    private CartRepository cartRepository;

    @Autowired
    private ProductColorRepository productColorRepository;

    @Autowired
    private ModelMapper modelMapper;

    @Override
    public List<ProductColorDTO> findByUser(AccountDTO accountDTO) {
        Account user = modelMapper.map(accountDTO, Account.class);
        List<Cart> cartItems = cartRepository.findByUser(user);

        return cartItems.stream().map(item -> {
            Productcolor productColor = productColorRepository.findById(item.getProductColorId()).orElse(null);
            if (productColor == null) return null;

            ProductColorDTO dto = new ProductColorDTO();
            dto.setId(productColor.getId());
            dto.setColor(productColor.getColor());
            dto.setPhoto(productColor.getPhoto());
            dto.setPrice(productColor.getPrice());
            dto.setValue(productColor.getValue());
            dto.setQuantity(item.getQuantity());
            dto.setVersionID(productColor.getVersionID().getProduct().getId());

            //Version
            dto.setVersion(productColor.getVersionID().getVersionname());
            //Product
            dto.setEngieType(productColor.getVersionID().getProduct().getEngieType());
            dto.setFuelConsumption(productColor.getVersionID().getProduct().getFuelConsumption());
            // Thêm tên sản phẩm
            dto.setProductName(productColor.getVersionID().getProduct().getName());

            return dto;
        }).filter(Objects::nonNull).collect(Collectors.toList());
    }

    @Override
    public void addToCart(AccountDTO accountDTO, ProductColorDTO request) {
        Account user = modelMapper.map(accountDTO, Account.class);
        List<Cart> existingList = cartRepository.findByUserAndProductColorId(user, request.getId());

        if (!existingList.isEmpty()) {
            Cart item = existingList.get(0);
            item.setQuantity(item.getQuantity() + request.getQuantity());
            cartRepository.save(item);
        } else {
            Cart item = new Cart();
            item.setUser(user);
            item.setProductColorId(request.getId());
            item.setQuantity(request.getQuantity());
            cartRepository.save(item);
        }
    }

    @Override
    public void updateCartItem(AccountDTO accountDTO, int productColorId, int quantity) {
        Account user = modelMapper.map(accountDTO, Account.class);
        List<Cart> items = cartRepository.findByUserAndProductColorId(user, productColorId);
        if (!items.isEmpty()) {
            Cart item = items.get(0);
            item.setQuantity(quantity);
            cartRepository.save(item);
        }
    }

    @Override
    public void removeFromCart(AccountDTO accountDTO, int productColorId) {
        Account user = modelMapper.map(accountDTO, Account.class);
        List<Cart> items = cartRepository.findByUserAndProductColorId(user, productColorId);
        items.forEach(cartRepository::delete);
    }
}

