package com.example.cua_hang_xe_may.repositories;

import com.example.cua_hang_xe_may.entities.Account;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AccountRepository extends JpaRepository<Account, Integer> {
    Optional<Account> findByUsername(String username);
    Optional<Account> findByEmail(String email);
    Optional<Account> findBySecurityCode(String securityCode);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
    
    // Count methods for statistics
    long countByStatus(String status);
    long countByRole(String role);
    
    // Search methods
    Page<Account> findByUsernameContainingOrEmailContaining(String username, String email, Pageable pageable);
}
