package com.example.cua_hang_xe_may.controller;

import com.example.cua_hang_xe_may.dto.AccountDTO;
import com.example.cua_hang_xe_may.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    @Autowired
    private AccountService accountService;

    @GetMapping
    public ResponseEntity<List<AccountDTO>> getAllAccounts() {
        return ResponseEntity.ok(accountService.getAllAccounts());
    }

    @GetMapping("/{input}")
    public ResponseEntity<AccountDTO> getAccount(@PathVariable String input) {
        try {
            // Thử parse sang Integer -> là ID
            Integer id = Integer.parseInt(input);
            return ResponseEntity.ok(accountService.getAccountById(id));
        } catch (NumberFormatException e) {
            // Không phải số -> là username
            return ResponseEntity.ok(accountService.getAccountByUsername(input));
        }
    }
    @GetMapping("/username/{username}")
    public ResponseEntity<AccountDTO> getAccountByUsername(@PathVariable String username) {
        return ResponseEntity.ok(accountService.getAccountByUsername(username));
    }

    @PostMapping
    public ResponseEntity<AccountDTO> createAccount(@RequestBody AccountDTO accountDTO) {
        return ResponseEntity.ok(accountService.createAccount(accountDTO));
    }

    @PutMapping("/{id}")
    public ResponseEntity<AccountDTO> updateAccount(@PathVariable Integer id, @RequestBody AccountDTO accountDTO) {
        return ResponseEntity.ok(accountService.updateAccount(id, accountDTO));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteAccount(@PathVariable Integer id) {
        accountService.deleteAccount(id);
        return ResponseEntity.noContent().build();
    }
}