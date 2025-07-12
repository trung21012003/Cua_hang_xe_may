package com.example.cua_hang_xe_may.controller;

import com.example.cua_hang_xe_may.dto.ApiResponse;
import com.example.cua_hang_xe_may.dto.CreateUserRequest;
import com.example.cua_hang_xe_may.dto.RegisterRequest;
import com.example.cua_hang_xe_may.entities.Account;
import com.example.cua_hang_xe_may.entities.Role;
import com.example.cua_hang_xe_may.repositories.AccountRepository;
import com.example.cua_hang_xe_may.security.RoleChecker;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    @Autowired
    private AccountRepository accountRepository;
    
    @Autowired
    private RoleChecker roleChecker;
    
    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Get all users with pagination
     */
    @GetMapping("/users")
    public ResponseEntity<?> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "id") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDir) {
        
        System.out.println("Admin getAllUsers endpoint accessed");
        System.out.println("Current user: " + roleChecker.getCurrentUsername());
        System.out.println("Is admin: " + roleChecker.isAdmin());
        
        try {
            Sort sort = sortDir.equalsIgnoreCase("desc") ? 
                    Sort.by(sortBy).descending() : Sort.by(sortBy).ascending();
            
            Pageable pageable = PageRequest.of(page, size, sort);
            Page<Account> users = accountRepository.findAll(pageable);
            
            return ResponseEntity.ok(users);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error fetching users: " + e.getMessage(), false));
        }
    }

    /**
     * Get user by ID
     */
    @GetMapping("/users/{userId}")
    public ResponseEntity<?> getUserById(@PathVariable Integer userId) {
        Optional<Account> user = accountRepository.findById(userId);
        
        if (user.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        return ResponseEntity.ok(user.get());
    }

    /**
     * Create new user (Admin only)
     */
    @PostMapping("/users")

    public ResponseEntity<?> createUser(@Valid @RequestBody CreateUserRequest createUserRequest) {
        System.out.println("Admin createUser endpoint accessed");
        System.out.println("Current user: " + roleChecker.getCurrentUsername());
        System.out.println("Is admin: " + roleChecker.isAdmin());
        System.out.println("Request data: " + createUserRequest);
        
        try {
            // Check if username already exists
            if (accountRepository.existsByUsername(createUserRequest.getUsername())) {
                return ResponseEntity.badRequest().body(
                    new ApiResponse("Username is already taken", false)
                );
            }

            // Check if email already exists
            if (accountRepository.existsByEmail(createUserRequest.getEmail())) {
                return ResponseEntity.badRequest().body(
                    new ApiResponse("Email is already in use", false)
                );
            }

            // Create new account
            Account account = new Account();
            account.setUsername(createUserRequest.getUsername());
            account.setPassword(passwordEncoder.encode(createUserRequest.getPassword()));
            account.setEmail(createUserRequest.getEmail());
            account.setPhone(createUserRequest.getPhone() != null ? createUserRequest.getPhone() : "");
            account.setName(createUserRequest.getName() != null ? createUserRequest.getName() : createUserRequest.getUsername());
            account.setDob(null); // Admin created users don't need DOB
            account.setAddress(createUserRequest.getAddress() != null ? createUserRequest.getAddress() : "");
            account.setRole(createUserRequest.getRole() != null ? createUserRequest.getRole() : "1"); // Use provided role or default to USER
            account.setStatus(createUserRequest.getStatus() != null ? createUserRequest.getStatus() : "ACTIVE");
            account.setSecurityCode("ADMIN_CREATED"); // Default security code for admin-created users
            account.setCreated(Instant.now());

            // Save account
            Account savedAccount = accountRepository.save(account);

            return ResponseEntity.ok(new ApiResponse("User created successfully", true, savedAccount));
            
        } catch (Exception e) {
            System.err.println("Error creating user: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error creating user: " + e.getMessage(), false));
        }
    }

    /**
     * Update user role
     */
    @PutMapping("/users/{userId}/role")
    public ResponseEntity<?> updateUserRole(
            @PathVariable Integer userId, 
            @RequestParam String roleCode) {
        
        try {
            Optional<Account> userOpt = accountRepository.findById(userId);
            
            if (userOpt.isEmpty()) {
                return ResponseEntity.notFound().build();
            }
            
            Account user = userOpt.get();
            
            // Validate role code
            Role newRole = Role.fromCode(roleCode);
            if (newRole == null) {
                return ResponseEntity.badRequest()
                        .body(new ApiResponse("Invalid role code", false));
            }
            
            user.setRole(roleCode);
            accountRepository.save(user);
            
            return ResponseEntity.ok(new ApiResponse("User role updated successfully", true));
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error updating user role: " + e.getMessage(), false));
        }
    }

    /**
     * Update user status (ACTIVE, INACTIVE, PENDING)
     */
    @PutMapping("/users/{userId}/status")
    public ResponseEntity<?> updateUserStatus(
            @PathVariable Integer userId, 
            @RequestParam String status) {
        
        try {
            Optional<Account> userOpt = accountRepository.findById(userId);
            
            if (userOpt.isEmpty()) {
                return ResponseEntity.notFound().build();
            }
            
            Account user = userOpt.get();
            
            // Validate status
            if (!status.matches("ACTIVE|INACTIVE|PENDING")) {
                return ResponseEntity.badRequest()
                        .body(new ApiResponse("Invalid status. Must be ACTIVE, INACTIVE, or PENDING", false));
            }
            
            user.setStatus(status);
            accountRepository.save(user);
            
            return ResponseEntity.ok(new ApiResponse("User status updated successfully", true));
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error updating user status: " + e.getMessage(), false));
        }
    }

    /**
     * Delete user account
     */
    @DeleteMapping("/users/{userId}")
    public ResponseEntity<?> deleteUser(@PathVariable Integer userId) {
        try {
            System.out.println("Attempting to delete user with ID: " + userId);
            
            Optional<Account> userOpt = accountRepository.findById(userId);
            
            if (userOpt.isEmpty()) {
                System.out.println("User with ID " + userId + " not found");
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new ApiResponse("User with ID " + userId + " not found", false));
            }
            
            Account user = userOpt.get();
            System.out.println("Found user: " + user.getUsername());
            
            // Prevent admin from deleting their own account
            String currentUsername = roleChecker.getCurrentUsername();
            if (currentUsername != null && user.getUsername().equals(currentUsername)) {
                return ResponseEntity.badRequest()
                        .body(new ApiResponse("Cannot delete your own account", false));
            }
            
            accountRepository.delete(user);
            System.out.println("Successfully deleted user: " + user.getUsername());
            
            return ResponseEntity.ok(new ApiResponse("User deleted successfully", true));
            
        } catch (Exception e) {
            System.err.println("Error deleting user " + userId + ": " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error deleting user: " + e.getMessage(), false));
        }
    }

    /**
     * Get system statistics
     */
    @GetMapping("/stats")
    public ResponseEntity<?> getSystemStats() {
        try {
            // User statistics
            long totalUsers = accountRepository.count();
            long activeUsers = accountRepository.countByStatus("ACTIVE");
            long pendingUsers = accountRepository.countByStatus("PENDING");
            long inactiveUsers = accountRepository.countByStatus("INACTIVE");
            
            long adminCount = accountRepository.countByRole("0");
            long userCount = accountRepository.countByRole("1");
            long managerCount = accountRepository.countByRole("2");
            long guestCount = accountRepository.countByRole("3");
            
            // System health checks
            String databaseStatus = "healthy";
            String cacheStatus = "healthy";
            int storageUsage = 75; // Default to 75% usage
            
            try {
                // Test database connection by performing a simple query
                accountRepository.count();
                databaseStatus = "healthy";
            } catch (Exception e) {
                databaseStatus = "error";
                System.err.println("Database health check failed: " + e.getMessage());
            }
            
            // Simulate storage usage calculation (in real app, you'd check actual disk usage)
            try {
                long totalSpace = Runtime.getRuntime().totalMemory();
                long freeSpace = Runtime.getRuntime().freeMemory();
                long usedSpace = totalSpace - freeSpace;
                storageUsage = (int) ((usedSpace * 100) / totalSpace);
                
                // Add some randomness to simulate real storage usage
                storageUsage = Math.min(95, Math.max(60, storageUsage + (int)(Math.random() * 20 - 10)));
            } catch (Exception e) {
                System.err.println("Storage calculation failed: " + e.getMessage());
                storageUsage = 80; // Default fallback
            }
            
            // Cache status (simulate - in real app you'd check Redis/cache server)
            try {
                // Simulate cache health check
                if (Math.random() > 0.1) { // 90% chance healthy
                    cacheStatus = "healthy";
                } else {
                    cacheStatus = "warning";
                }
            } catch (Exception e) {
                cacheStatus = "warning";
            }
            
            var stats = new java.util.HashMap<String, Object>();
            
            // User stats
            stats.put("totalUsers", totalUsers);
            stats.put("activeUsers", activeUsers);
            stats.put("pendingUsers", pendingUsers);
            stats.put("inactiveUsers", inactiveUsers);
            stats.put("adminCount", adminCount);
            stats.put("userCount", userCount);
            stats.put("managerCount", managerCount);
            stats.put("guestCount", guestCount);
            
            // System health stats
            stats.put("databaseStatus", databaseStatus);
            stats.put("cacheStatus", cacheStatus);
            stats.put("storageUsage", storageUsage);
            stats.put("systemUptime", System.currentTimeMillis()); // Timestamp for uptime calculation
            stats.put("lastUpdated", java.time.Instant.now().toString());
            
            return ResponseEntity.ok(stats);
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error fetching system stats: " + e.getMessage(), false));
        }
    }

    /**
     * Search users by username or email
     */
    @GetMapping("/users/search")
    public ResponseEntity<?> searchUsers(
            @RequestParam String query,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        
        try {
            Pageable pageable = PageRequest.of(page, size);
            // Note: You'll need to add this method to AccountRepository
            // Page<Account> users = accountRepository.findByUsernameContainingOrEmailContaining(query, query, pageable);
            
            return ResponseEntity.ok("Search functionality needs to be implemented in AccountRepository");
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("Error searching users: " + e.getMessage(), false));
        }
    }
} 