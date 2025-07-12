package com.example.cua_hang_xe_may.service;

import com.example.cua_hang_xe_may.dto.ProductColorDTO;
import com.example.cua_hang_xe_may.entities.Productcolor;
import com.example.cua_hang_xe_may.repositories.ProductColorRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class ProductColorServiceImpl implements ProductColorService {
    @Autowired
    private ProductColorRepository productColorRepository;

    @Autowired
    ModelMapper modelMapper;

    @Override
    public List<ProductColorDTO> findAll() {
        return productColorRepository.findAll().stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    @Override
    public ProductColorDTO findById(Integer id) {
        return productColorRepository.findById(id)
                .map(this::mapToDTO)
                .orElse(null);
    }
    private ProductColorDTO mapToDTO(Productcolor entity) {
        return modelMapper.map(entity, ProductColorDTO.class);
    }
}
