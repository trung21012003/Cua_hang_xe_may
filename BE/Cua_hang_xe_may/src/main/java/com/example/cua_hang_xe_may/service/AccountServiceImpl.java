package com.example.cua_hang_xe_may.service;

import com.example.cua_hang_xe_may.dto.AccountDTO;
import com.example.cua_hang_xe_may.entities.Account;

import com.example.cua_hang_xe_may.repositories.AccountRepository;
import com.example.cua_hang_xe_may.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class AccountServiceImpl implements AccountService {

    @Autowired
    private AccountRepository accountRepository;

    @Override
    public List<AccountDTO> getAllAccounts() {
        return accountRepository.findAll().stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    @Override
    public AccountDTO getAccountById(Integer id) {
        Account account = accountRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Account not found"));
        return convertToDTO(account);
    }

    @Override
    public AccountDTO getAccountByUsername(String username) {
        Account account = accountRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Account not found"));
        return convertToDTO(account);
    }

    @Override
    public AccountDTO createAccount(AccountDTO accountDTO) {
        Account account = convertToEntity(accountDTO);
        account = accountRepository.save(account);
        return convertToDTO(account);
    }

    @Override
    public AccountDTO updateAccount(Integer id, AccountDTO accountDTO) {
        Account existingAccount = accountRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Account not found"));
        updateEntityFromDTO(existingAccount, accountDTO);
        existingAccount = accountRepository.save(existingAccount);
        return convertToDTO(existingAccount);
    }

    @Override
    public void deleteAccount(Integer id) {
        if (!accountRepository.existsById(id)) {
            throw new RuntimeException("Account not found");
        }
        accountRepository.deleteById(id);
    }

    private AccountDTO convertToDTO(Account account) {
        AccountDTO dto = new AccountDTO();
        dto.setId(account.getId());
        dto.setUsername(account.getUsername());
        dto.setPhone(account.getPhone());
        dto.setEmail(account.getEmail());
        dto.setRole(account.getRole());
        dto.setStatus(account.getStatus());
        dto.setName(account.getName());
        dto.setDob(account.getDob());
        dto.setAddress(account.getAddress());
        dto.setCreated(account.getCreated());
        dto.setAvatar(account.getAvatar());
        return dto;
    }

    private Account convertToEntity(AccountDTO dto) {
        Account account = new Account();
        account.setUsername(dto.getUsername());
        account.setPhone(dto.getPhone());
        account.setEmail(dto.getEmail());
        account.setRole(dto.getRole());
        account.setStatus(dto.getStatus());
        account.setSecurityCode("SERVICE_CREATED"); // Default security code for service-created accounts
        account.setName(dto.getName());
        account.setDob(dto.getDob());
        account.setAddress(dto.getAddress());
        account.setCreated(dto.getCreated());
        account.setAvatar(dto.getAvatar());
        return account;
    }

    private void updateEntityFromDTO(Account account, AccountDTO dto) {
        account.setUsername(dto.getUsername());
        account.setPhone(dto.getPhone());
        account.setEmail(dto.getEmail());
        account.setRole(dto.getRole());
        account.setStatus(dto.getStatus());
        account.setName(dto.getName());
        account.setDob(dto.getDob());
        account.setAddress(dto.getAddress());
        account.setCreated(dto.getCreated());
        account.setAvatar(dto.getAvatar());
    }
}