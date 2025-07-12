package com.example.cua_hang_xe_may.service;

import com.example.cua_hang_xe_may.dto.ProductColorDTO;

import java.util.List;


public interface ProductColorService {
    public List<ProductColorDTO> findAll();
    public ProductColorDTO findById(Integer id);

}
