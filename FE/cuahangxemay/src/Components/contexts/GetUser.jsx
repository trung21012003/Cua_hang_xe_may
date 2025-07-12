// src/contexts/AuthContext.js
import React, { createContext, useEffect, useState, useCallback } from "react";
import { jwtDecode } from "jwt-decode";
import axios from "axios";

export const UserContext = createContext({
  isLoggedIn: false,
  setIsLoggedIn: () => {},
  isLoading: true,
  user: null,
  setUser: () => {},
});

export const UserProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [isLoading, setIsLoading] = useState(true); // Thêm trạng thái loading

  const checkAuth = useCallback(async () => {
    setIsLoading(true);
    const token = localStorage.getItem("jwtToken");
    if (!token) {
      setIsLoggedIn(false);
      setUser(null);
      setIsLoading(false);
      return;
    }

    try {
      const decoded = jwtDecode(token);
      const currentTime = Date.now() / 1000;

      if (decoded.exp < currentTime) {
        localStorage.removeItem("jwtToken");
        setIsLoggedIn(false);
        setUser(null);
      } else {
        setIsLoggedIn(true);
        const res = await axios.get(
          `http://localhost:8080/api/accounts/${decoded.sub}`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );
        setUser(res.data);
        console.log("User data:", res.data);
      }
    } catch (error) {
      console.error("Lỗi kiểm tra token:", error);
      localStorage.removeItem("jwtToken");
      setIsLoggedIn(false);
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    checkAuth(); // Kiểm tra token khi mount
  }, [checkAuth]);

  return (
    <UserContext.Provider
      value={{ user, isLoggedIn, setIsLoggedIn, setUser, isLoading, checkAuth }}
    >
      {children}
    </UserContext.Provider>
  );
};
