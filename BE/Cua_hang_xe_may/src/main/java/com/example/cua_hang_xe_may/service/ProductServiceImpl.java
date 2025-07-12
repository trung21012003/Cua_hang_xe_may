package com.example.cua_hang_xe_may.service;

import com.example.cua_hang_xe_may.dto.AccountDTO;
import com.example.cua_hang_xe_may.dto.ProductColorDTO;
import com.example.cua_hang_xe_may.dto.ProductDTO;
import com.example.cua_hang_xe_may.dto.ProductVersionDTO;
import com.example.cua_hang_xe_may.entities.*;
import com.example.cua_hang_xe_may.repositories.CartRepository;
import com.example.cua_hang_xe_may.repositories.ProductColorRepository;
import com.example.cua_hang_xe_may.repositories.ProductRepository;
import com.example.cua_hang_xe_may.repositories.ProductVersionRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class ProductServiceImpl implements ProductService {
    @Autowired
    private ProductRepository productRepository;
    @Autowired
    private ModelMapper modelMapper;
    @Autowired
    private ProductVersionRepository productVersionRepository;
    @Autowired
    private CartRepository cartRepository;
    @Autowired
    private ProductColorRepository productColorRepository;


    @Override
    public List<ProductDTO> findAll() {
        return productRepository.findAll().stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    @Override
    public ProductDTO findById(Integer id) {
        ProductDTO productDTO = productRepository.findById(id)
                .map(this::mapToDTO)
                .orElse(null);
        if(productDTO != null) {
            List<Productversion> versions = productVersionRepository.findAllByProductId(id);
            List<ProductVersionDTO> versionDTOS = versions.stream().map(v -> {
                ProductVersionDTO productVersionDTO = new ProductVersionDTO();
                productVersionDTO.setId(v.getId());
                productVersionDTO.setVersionName(v.getVersionname());
                productVersionDTO.setPrice(v.getPrice());
                productVersionDTO.setProductID(v.getProduct().getId());

                productVersionDTO.setColors(
                        v.getColors().stream().map(c -> {
                            ProductColorDTO productColorDTO = new ProductColorDTO();
                            productColorDTO.setId(c.getId());
                            productColorDTO.setVersionID(v.getId());
                            productColorDTO.setColor(c.getColor());
                            productColorDTO.setPrice(c.getPrice());
                            productColorDTO.setPhoto(c.getPhoto());
                            productColorDTO.setQuantity(c.getQuantity());
                            productColorDTO.setValue(c.getValue());
                            return productColorDTO;
                        }).collect(Collectors.toList())
                );
                return productVersionDTO;
            }).collect(Collectors.toList());
            productDTO.setVersionColors(versionDTOS);
            
            // Calculate total stock
            int totalStock = versionDTOS.stream()
                    .flatMap(version -> version.getColors().stream())
                    .mapToInt(color -> color.getQuantity() != null ? color.getQuantity() : 0)
                    .sum();
            productDTO.setTotalStock(totalStock);
        }
        return productDTO;
    }

    @Override
    public void deleteById(Integer id) {
        productRepository.deleteById(id);
    }

    /**
     * Public method to convert Product entity to ProductDTO
     * Can be used by controllers for mapping
     */
    public ProductDTO mapToDTO(Product product) {
        ProductDTO dto = modelMapper.map(product, ProductDTO.class);
        if (product.getBrand() != null) {
            dto.setBrandName(product.getBrand().getName());
        }
        if (product.getMotoline() != null) {
            dto.setMotolineName(product.getMotoline().getName());
        }
        return dto;
    }

    @Override
    public ProductDTO save(ProductDTO dto) {
        Product product = mapToEntity(dto);
        Product saved = productRepository.save(product);
        return mapToDTO(saved);
    }
    
    private Product mapToEntity(ProductDTO dto) {
        return modelMapper.map(dto, Product.class);
    }

    /**
     * Find products by brand name
     */
    public List<ProductDTO> findByBrandName(String brandName) {
        return productRepository.findAll().stream()
                .filter(product -> product.getBrand() != null && brandName.equals(product.getBrand().getName()))
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    /**
     * Find products with low stock
     */
    public List<ProductDTO> findLowStockProducts(int threshold) {
        return findAll().stream()
                .filter(product -> {
                    int totalStock = 0;
                    if (product.getVersionColors() != null) {
                        totalStock = product.getVersionColors().stream()
                                .flatMap(version -> version.getColors() != null ? version.getColors().stream() : java.util.stream.Stream.empty())
                                .mapToInt(color -> color.getQuantity() != null ? color.getQuantity() : 0)
                                .sum();
                    }
                    return totalStock < threshold;
                })
                .collect(Collectors.toList());
    }

    /**
     * Search products by keyword
     */
    public List<ProductDTO> searchProducts(String keyword) {
        if (keyword == null || keyword.trim().isEmpty()) {
            return findAll();
        }
        
        String lowerKeyword = keyword.toLowerCase();
        return findAll().stream()
                .filter(product -> 
                    (product.getName() != null && product.getName().toLowerCase().contains(lowerKeyword)) ||
                    (product.getDescription() != null && product.getDescription().toLowerCase().contains(lowerKeyword)) ||
                    (product.getBrandName() != null && product.getBrandName().toLowerCase().contains(lowerKeyword)) ||
                    (product.getEngieType() != null && product.getEngieType().toLowerCase().contains(lowerKeyword))
                )
                .collect(Collectors.toList());
    }

    /**
     * Find products by price range
     */
    public List<ProductDTO> findByPriceRange(Double minPrice, Double maxPrice) {
        return findAll().stream()
                .filter(product -> {
                    if (product.getPrice() == null) return false;
                    boolean aboveMin = minPrice == null || product.getPrice() >= minPrice;
                    boolean belowMax = maxPrice == null || product.getPrice() <= maxPrice;
                    return aboveMin && belowMax;
                })
                .collect(Collectors.toList());
    }

    /**
     * Get unique brand names
     */
    public List<String> getUniqueBrandNames() {
        return productRepository.findAll().stream()
                .filter(product -> product.getBrand() != null)
                .map(product -> product.getBrand().getName())
                .distinct()
                .sorted()
                .collect(Collectors.toList());
    }

    /**
     * Get products count by brand
     */
    public java.util.Map<String, Long> getProductCountByBrand() {
        return productRepository.findAll().stream()
                .collect(Collectors.groupingBy(
                    product -> product.getBrand() != null ? product.getBrand().getName() : "Unknown",
                    Collectors.counting()
                ));
    }

    /**
     * Check if product exists
     */
    public boolean existsById(Integer id) {
        return productRepository.existsById(id);
    }

    /**
     * Update product stock
     */
    public void updateStock(Integer productColorId, Integer newQuantity) {
        Optional<Productcolor> colorOpt = productColorRepository.findById(productColorId);
        if (colorOpt.isPresent()) {
            Productcolor color = colorOpt.get();
            color.setQuantity(newQuantity);
            productColorRepository.save(color);
        }
    }
}
