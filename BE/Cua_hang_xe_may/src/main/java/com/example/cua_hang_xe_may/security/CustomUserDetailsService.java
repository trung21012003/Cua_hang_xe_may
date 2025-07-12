package com.example.cua_hang_xe_may.security;

import com.example.cua_hang_xe_may.entities.Account;
import com.example.cua_hang_xe_may.entities.Role;
import com.example.cua_hang_xe_may.repositories.AccountRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;


@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final AccountRepository accountRepository;

    public CustomUserDetailsService(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        java.util.Optional<Account> account = accountRepository.findByUsername(username);
        if (account.isEmpty()) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }

        Account accountData = account.get();

        // Check if account is active
        if (!"ACTIVE".equals(accountData.getStatus())) {
            throw new UsernameNotFoundException("Account is not active. Please verify your email.");
        }

        Role role = Role.fromCode(accountData.getRole());

        return org.springframework.security.core.userdetails.User.builder()
                .username(username)
                .password(accountData.getPassword())
                .authorities(Collections.singletonList(new SimpleGrantedAuthority(role.getAuthority())))
                .build();
    }


}
