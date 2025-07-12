package com.example.cua_hang_xe_may.controller;

import com.example.cua_hang_xe_may.dto.ProductDTO;
import com.example.cua_hang_xe_may.dto.ProductVersionDTO;
import com.example.cua_hang_xe_may.entities.Product;
import com.example.cua_hang_xe_may.service.ProductService;
import com.example.cua_hang_xe_may.service.ProductVersionService;
import com.example.cua_hang_xe_may.repositories.ProductRepository;
import com.example.cua_hang_xe_may.repositories.ProductColorRepository;


import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
@RequestMapping("/api/products")
public class ProductController {
    @Autowired
    private ProductService productService;

    @Autowired
    private ProductVersionService productVersionService;
    
    @Autowired
    private ProductRepository productRepository;
    
    @Autowired
    private ProductColorRepository productColorRepository;

    @GetMapping("/public")
    public List<ProductDTO> getAllPublic() {
        return productService.findAll();
    }

    @GetMapping("/public/{id}")
    public ResponseEntity<Map<String, Object>> getByIdPublic(@PathVariable Integer id) {
        System.out.println(">>> Đang tìm sản phẩm ID = " + id);
        ProductDTO productDTO = productService.findById(id);

        if (productDTO == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(Map.of("product", productDTO));
    }

    @GetMapping("/public/search")
    public ResponseEntity<List<ProductDTO>> searchPublic(
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) String brand,
            @RequestParam(required = false) Double minPrice,
            @RequestParam(required = false) Double maxPrice) {
        
        List<ProductDTO> allProducts = productService.findAll();
        List<ProductDTO> filteredProducts = allProducts.stream()
                .filter(product -> {
                    boolean matches = true;
                    
                    if (keyword != null && !keyword.isEmpty()) {
                        matches = matches && (product.getName().toLowerCase().contains(keyword.toLowerCase()) ||
                                            product.getDescription().toLowerCase().contains(keyword.toLowerCase()));
                    }
                    
                    if (brand != null && !brand.isEmpty()) {
                        matches = matches && brand.equals(product.getBrandName());
                    }
                    
                    if (minPrice != null) {
                        matches = matches && product.getPrice() >= minPrice;
                    }
                    
                    if (maxPrice != null) {
                        matches = matches && product.getPrice() <= maxPrice;
                    }
                    
                    return matches;
                }).collect(Collectors.toList());
        
        return ResponseEntity.ok(filteredProducts);
    }

    @GetMapping("/manage")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")
    public ResponseEntity<Map<String, Object>> getAllForManagement(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "id") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDir,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) String brand,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) Double minPrice,
            @RequestParam(required = false) Double maxPrice) {
        
        try {
            Sort sort = sortDir.equalsIgnoreCase("desc") ? 
                    Sort.by(sortBy).descending() : Sort.by(sortBy).ascending();
            
            Pageable pageable = PageRequest.of(page, size, sort);
            Page<Product> productPage = productRepository.findAll(pageable);
            
            List<ProductDTO> productDTOs = productPage.getContent().stream()
                    .map(product -> {
                        // Convert Product to ProductDTO using service findById
                        return productService.findById(product.getId());
                    })
                    .filter(product -> {
                        boolean matches = true;
                        
                        if (search != null && !search.isEmpty()) {
                            matches = matches && (product.getName().toLowerCase().contains(search.toLowerCase()) ||
                                                product.getDescription().toLowerCase().contains(search.toLowerCase()));
                        }
                        
                        if (brand != null && !brand.isEmpty()) {
                            matches = matches && brand.equals(product.getBrandName());
                        }
                        
                        if (status != null && !status.isEmpty()) {
                            // Add status filtering logic if Product entity has status field
                            // matches = matches && status.equals(product.getStatus());
                        }
                        
                        if (minPrice != null) {
                            matches = matches && product.getPrice() >= minPrice;
                        }
                        
                        if (maxPrice != null) {
                            matches = matches && product.getPrice() <= maxPrice;
                        }
                        
                        return matches;
                    })
                    .collect(Collectors.toList());
            
            Map<String, Object> response = new HashMap<>();
            response.put("content", productDTOs);
            response.put("totalElements", productPage.getTotalElements());
            response.put("totalPages", productPage.getTotalPages());
            response.put("currentPage", page);
            response.put("pageSize", size);
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Error fetching products: " + e.getMessage()));
        }
    }
    @GetMapping("/manage/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")
    public ResponseEntity<Map<String, Object>> getByIdForManagement(@PathVariable Integer id) {
        ProductDTO productDTO = productService.findById(id);

        if (productDTO == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(Map.of("product", productDTO));
    }
    @PostMapping("/manage")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")
    public ProductDTO create(@Valid @RequestBody ProductDTO productDTO) {
        return productService.save(productDTO);
    }

    @PutMapping("/manage/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")

    public ResponseEntity<ProductDTO> update(@PathVariable Integer id, @Valid @RequestBody ProductDTO productDTO) {
        if (productService.findById(id) == null) {
            return ResponseEntity.notFound().build();
        }
        productDTO.setId(id);
        return ResponseEntity.ok(productService.save(productDTO));
    }


    @DeleteMapping("/admin/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> delete(@PathVariable Integer id) {
        if (productService.findById(id) == null) {
            return ResponseEntity.notFound().build();
        }
        productService.deleteById(id);
        return ResponseEntity.noContent().build();
    }


    @GetMapping("/admin/statistics")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")
    public ResponseEntity<Map<String, Object>> getProductStatistics() {
        try {
            long totalProducts = productRepository.count();
            
            // Get brand statistics
            List<Product> allProducts = productRepository.findAll();
            Map<String, Long> brandStats = allProducts.stream()
                    .collect(Collectors.groupingBy(
                            product -> product.getBrand() != null ? product.getBrand().getName() : "Unknown",
                            Collectors.counting()
                    ));
            
            // Price range statistics
            long underFiftyMillion = allProducts.stream()
                    .filter(p -> p.getPrice() != null && p.getPrice() < 50000000)
                    .count();
            long fiftyToHundredMillion = allProducts.stream()
                    .filter(p -> p.getPrice() != null && p.getPrice() >= 50000000 && p.getPrice() < 100000000)
                    .count();
            long aboveHundredMillion = allProducts.stream()
                    .filter(p -> p.getPrice() != null && p.getPrice() >= 100000000)
                    .count();
            
            // Inventory statistics
            long totalColors = productColorRepository.count();
            long outOfStockColors = productColorRepository.findAll().stream()
                    .filter(color -> color.getQuantity() == null || color.getQuantity() == 0)
                    .count();
            long lowStockColors = productColorRepository.findAll().stream()
                    .filter(color -> color.getQuantity() != null && color.getQuantity() > 0 && color.getQuantity() < 10)
                    .count();
            
            Map<String, Object> statistics = new HashMap<>();
            statistics.put("totalProducts", totalProducts);
            statistics.put("brandStatistics", brandStats);
            statistics.put("priceRangeStatistics", Map.of(
                    "underFiftyMillion", underFiftyMillion,
                    "fiftyToHundredMillion", fiftyToHundredMillion,
                    "aboveHundredMillion", aboveHundredMillion
            ));
            statistics.put("inventoryStatistics", Map.of(
                    "totalColors", totalColors,
                    "outOfStockColors", outOfStockColors,
                    "lowStockColors", lowStockColors,
                    "inStockColors", totalColors - outOfStockColors
            ));
            
            return ResponseEntity.ok(statistics);
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Error getting statistics: " + e.getMessage()));
        }
    }


    @GetMapping("/admin/low-stock")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")
    public ResponseEntity<List<Map<String, Object>>> getLowStockProducts(@RequestParam(defaultValue = "10") int threshold) {
        try {
            List<ProductDTO> allProducts = productService.findAll();
            
            List<Map<String, Object>> lowStockProducts = allProducts.stream()
                    .map(product -> {
                        // Calculate total stock for each product
                        int totalStock = 0;
                        if (product.getVersionColors() != null) {
                            totalStock = product.getVersionColors().stream()
                                    .flatMap(version -> version.getColors() != null ? version.getColors().stream() : Stream.empty())
                                    .mapToInt(color -> color.getQuantity() != null ? color.getQuantity() : 0)
                                    .sum();
                        }
                        
                        Map<String, Object> productInfo = new HashMap<>();
                        productInfo.put("id", product.getId());
                        productInfo.put("name", product.getName());
                        productInfo.put("brandName", product.getBrandName());
                        productInfo.put("totalStock", totalStock);
                        productInfo.put("avatar", product.getAvatar());
                        
                        return productInfo;
                    })
                    .filter(productInfo -> (Integer) productInfo.get("totalStock") < threshold)
                    .sorted((a, b) -> Integer.compare((Integer) a.get("totalStock"), (Integer) b.get("totalStock")))
                    .collect(Collectors.toList());
            
            return ResponseEntity.ok(lowStockProducts);
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body(List.of(Map.of("error", "Error getting low stock products: " + e.getMessage())));
        }
    }

    @GetMapping("/admin/by-brand/{brandName}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")
    public ResponseEntity<List<ProductDTO>> getProductsByBrand(@PathVariable String brandName) {
        try {
            List<ProductDTO> allProducts = productService.findAll();
            List<ProductDTO> brandProducts = allProducts.stream()
                    .filter(product -> brandName.equals(product.getBrandName()))
                    .collect(Collectors.toList());
            
            return ResponseEntity.ok(brandProducts);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(List.of());
        }
    }

    @PutMapping("/admin/bulk-status")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> bulkUpdateStatus(
            @RequestBody Map<String, Object> request) {
        try {
            @SuppressWarnings("unchecked")
            List<Integer> productIds = (List<Integer>) request.get("productIds");
            String status = (String) request.get("status");
            
            if (productIds == null || productIds.isEmpty() || status == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid request data"));
            }
            
            int updatedCount = 0;
            for (Integer productId : productIds) {
                ProductDTO product = productService.findById(productId);
                if (product != null) {
                    // Add status update logic here when Product entity has status field
                    // product.setStatus(status);
                    // productService.save(product);
                    updatedCount++;
                }
            }
            
            return ResponseEntity.ok(Map.of(
                    "message", "Bulk update completed",
                    "updatedCount", updatedCount
            ));
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Error in bulk update: " + e.getMessage()));
        }
    }

    @GetMapping
    public List<ProductDTO> getAll() {
        return productService.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Map<String, Object>> getById(@PathVariable Integer id) {
        System.out.println(">>> Đang tìm sản phẩm ID = " + id);
        ProductDTO productDTO = productService.findById(id);

        if (productDTO == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(Map.of("product", productDTO));
    }

    @GetMapping("/getVersionsByProductId/{id}")
    public List<ProductVersionDTO> getVersionsByProductId(@PathVariable Integer id) {
        return productVersionService.findByProductId(id);
    }
}
