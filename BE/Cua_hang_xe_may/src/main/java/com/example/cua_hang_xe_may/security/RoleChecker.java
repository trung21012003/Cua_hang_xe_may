package com.example.cua_hang_xe_may.security;

import com.example.cua_hang_xe_may.entities.Account;
import com.example.cua_hang_xe_may.entities.Role;
import com.example.cua_hang_xe_may.repositories.AccountRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.security.Principal;
import java.util.Optional;

@Component
public class RoleChecker {
    
    private final AccountRepository accountRepository;
    
    public RoleChecker(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    public boolean isAdmin() {
        return hasRole(Role.ADMIN);
    }
    public boolean isManager() {
        return hasRole(Role.MANAGER);
    }
    public boolean isUser() {
        return hasRole(Role.USER);
    }
    public boolean isAdminOrManager() {
        return isAdmin() || isManager();
    }

    public boolean hasRole(Role role) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        
        return authentication.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals(role.getAuthority()));
    }

    public Role getCurrentUserRole() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return Role.GUEST;
        }
        
        String username = authentication.getName();
        Optional<Account> account = accountRepository.findByUsername(username);
        
        if (account.isPresent()) {
            return Role.fromCode(account.get().getRole());
        }
        
        return Role.USER;
    }

    public boolean canAccessUserResource(String resourceOwnerUsername) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        
        String currentUsername = authentication.getName();
        
        // User can access their own resources
        if (currentUsername.equals(resourceOwnerUsername)) {
            return true;
        }
        
        // Admin and Manager can access any user's resources
        return isAdminOrManager();
    }

    public boolean canAccessUserResource(Integer resourceOwnerUserId) {
        Optional<Account> resourceOwner = accountRepository.findById(resourceOwnerUserId);
        if (resourceOwner.isEmpty()) {
            return false;
        }
        
        return canAccessUserResource(resourceOwner.get().getUsername());
    }
    public String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        return authentication.getName();
    }

    public Optional<Account> getCurrentUser() {
        String username = getCurrentUsername();
        if (username == null) {
            return Optional.empty();
        }
        return accountRepository.findByUsername(username);
    }
} 