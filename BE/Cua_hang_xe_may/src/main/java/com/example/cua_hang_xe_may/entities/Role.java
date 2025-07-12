package com.example.cua_hang_xe_may.entities;

public enum Role {
    ADMIN("0", "ROLE_ADMIN"),
    USER("1", "ROLE_USER"),
    MANAGER("2", "ROLE_MANAGER"),
    GUEST("3", "ROLE_GUEST");

    private final String code;
    private final String authority;

    Role(String code, String authority) {
        this.code = code;
        this.authority = authority;
    }

    public String getCode() {
        return code;
    }

    public String getAuthority() {
        return authority;
    }

    public static Role fromCode(String code) {
        for (Role role : Role.values()) {
            if (role.code.equals(code)) {
                return role;
            }
        }
        return USER; // Default role
    }

    public static Role fromAuthority(String authority) {
        for (Role role : Role.values()) {
            if (role.authority.equals(authority)) {
                return role;
            }
        }
        return USER; // Default role
    }
} 