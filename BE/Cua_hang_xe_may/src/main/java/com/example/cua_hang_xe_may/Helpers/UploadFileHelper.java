package com.example.cua_hang_xe_may.Helpers;

import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.core.io.Resource;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/files")
public class UploadFileHelper {
    private final String uploadDir = "uploads/product-images/";

    @GetMapping("/{filename:.+}")
    public ResponseEntity<Resource> getFile(@PathVariable String filename) {
        try {
            Path file = Paths.get(uploadDir).resolve(filename);
            Resource resource = new UrlResource(file.toUri());

            if (resource.exists() || resource.isReadable()) {
                return ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"" + resource.getFilename() + "\"")
                        .body(resource);
            } else {
                return ResponseEntity.notFound().build();
            }

        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }
    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file) {
        try {
            Path uploadPath = Paths.get("uploads/product-images");

            // Tạo thư mục nếu chưa có
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
            }

            // Lưu file vào thư mục
            String filename = file.getOriginalFilename();
            Path filePath = uploadPath.resolve(filename);
            file.transferTo(filePath.toFile());

            return ResponseEntity.ok("Upload thành công: " + filename);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("Upload thất bại");
        }
    }

}
