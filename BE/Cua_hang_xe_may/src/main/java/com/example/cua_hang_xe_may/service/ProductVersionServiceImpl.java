package com.example.cua_hang_xe_may.service;

import com.example.cua_hang_xe_may.dto.ProductColorDTO;
import com.example.cua_hang_xe_may.dto.ProductVersionDTO;
import com.example.cua_hang_xe_may.entities.Productversion;
import com.example.cua_hang_xe_may.repositories.ProductVersionRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class ProductVersionServiceImpl implements ProductVersionService {
    @Autowired
    ProductVersionRepository productVersionRepository;

    @Autowired
    ModelMapper modelMapper;
    @Override
    public List<ProductVersionDTO> findAll() {
        return productVersionRepository.findAll().stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    @Override
    public List<ProductVersionDTO> findByProductId(Integer id) {
        return productVersionRepository.findById(id).stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }
    private ProductVersionDTO mapToDTO(Productversion entity) {
        ProductVersionDTO dto = modelMapper.map(entity, ProductVersionDTO.class);
        List<ProductColorDTO> colors = entity.getColors().stream()
                .map(color -> modelMapper.map(color, ProductColorDTO.class))
                .collect(Collectors.toList());
        dto.setColors(colors);
        return dto;
    }
}
