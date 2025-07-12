package com.example.cua_hang_xe_may.service;

import com.example.cua_hang_xe_may.dto.AccountDTO;
import com.example.cua_hang_xe_may.dto.ProductColorDTO;
import com.example.cua_hang_xe_may.dto.ProductDTO;
import com.example.cua_hang_xe_may.entities.Cart;
import com.example.cua_hang_xe_may.entities.Product;
import com.example.cua_hang_xe_may.entities.Productversion;

import java.util.List;

public interface ProductService {
    public List<ProductDTO> findAll();
    public ProductDTO findById(Integer id);
     public ProductDTO save(ProductDTO productDTO);
    void deleteById(Integer id);
}
