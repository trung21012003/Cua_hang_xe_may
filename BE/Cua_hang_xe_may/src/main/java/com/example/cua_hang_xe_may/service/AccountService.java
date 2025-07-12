package com.example.cua_hang_xe_may.service;

import com.example.cua_hang_xe_may.dto.AccountDTO;

import java.util.List;

public interface AccountService {
    List<AccountDTO> getAllAccounts();
    AccountDTO getAccountById(Integer id);

    AccountDTO getAccountByUsername(String username);
    AccountDTO createAccount(AccountDTO accountDTO);
    AccountDTO updateAccount(Integer id, AccountDTO accountDTO);
    void deleteAccount(Integer id);
}