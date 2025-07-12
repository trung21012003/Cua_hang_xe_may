package com.example.cua_hang_xe_may.config;

import com.example.cua_hang_xe_may.dto.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Xử lý lỗi validation từ @Valid annotation
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse> handleValidationExceptions(MethodArgumentNotValidException ex) {
        // Tạo map chứa các lỗi validation
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        // Tạo message tổng hợp từ các lỗi
        String combinedMessage = errors.values().stream()
                .collect(Collectors.joining(", "));

        // Trả về response với format thống nhất
        ApiResponse response = new ApiResponse(
                "Dữ liệu không hợp lệ: " + combinedMessage,
                false,
                errors
        );

        return ResponseEntity.badRequest().body(response);
    }

    /**
     * Xử lý các lỗi chung khác
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse> handleGenericException(Exception ex) {
        ApiResponse response = new ApiResponse(
                "Đã xảy ra lỗi: " + ex.getMessage(),
                false
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    /**
     * Xử lý lỗi IllegalArgumentException
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse> handleIllegalArgumentException(IllegalArgumentException ex) {
        ApiResponse response = new ApiResponse(
                ex.getMessage(),
                false
        );
        return ResponseEntity.badRequest().body(response);
    }
} 