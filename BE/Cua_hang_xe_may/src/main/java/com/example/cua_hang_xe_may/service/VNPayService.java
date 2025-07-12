package com.example.cua_hang_xe_may.service;

import com.example.cua_hang_xe_may.config.VNPayConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

@Service
public class VNPayService {

    @Autowired
    private VNPayConfig vnPayConfig;

    public String createPaymentUrl(String orderId, double amount, String orderInfo, String ipAddress) {
        try {
            String vnp_Version = "2.1.0";
            String vnp_Command = "pay";
            String vnp_TmnCode = vnPayConfig.getTerminalId();
            String vnp_Amount = String.valueOf((long) (amount * 100)); // Convert to VND (smallest unit)
            String vnp_CurrCode = "VND";
            String vnp_TxnRef = orderId;
            String vnp_OrderInfo = orderInfo;
            String vnp_OrderType = "other";
            String vnp_Locale = "vn";
            String vnp_ReturnUrl = vnPayConfig.getReturnUrl();
            String vnp_IpAddr = ipAddress;

            Calendar cld = Calendar.getInstance(TimeZone.getTimeZone("Etc/GMT+7"));
            SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
            String vnp_CreateDate = formatter.format(cld.getTime());

            cld.add(Calendar.MINUTE, 15);
            String vnp_ExpireDate = formatter.format(cld.getTime());

            Map<String, String> vnp_Params = new HashMap<>();
            vnp_Params.put("vnp_Version", vnp_Version);
            vnp_Params.put("vnp_Command", vnp_Command);
            vnp_Params.put("vnp_TmnCode", vnp_TmnCode);
            vnp_Params.put("vnp_Amount", vnp_Amount);
            vnp_Params.put("vnp_CurrCode", vnp_CurrCode);
            vnp_Params.put("vnp_TxnRef", vnp_TxnRef);
            vnp_Params.put("vnp_OrderInfo", vnp_OrderInfo);
            vnp_Params.put("vnp_OrderType", vnp_OrderType);
            vnp_Params.put("vnp_Locale", vnp_Locale);
            vnp_Params.put("vnp_ReturnUrl", vnp_ReturnUrl);
            vnp_Params.put("vnp_IpAddr", vnp_IpAddr);
            vnp_Params.put("vnp_CreateDate", vnp_CreateDate);
            vnp_Params.put("vnp_ExpireDate", vnp_ExpireDate);

            List<String> fieldNames = new ArrayList<>(vnp_Params.keySet());
            Collections.sort(fieldNames);
            StringBuilder hashData = new StringBuilder();
            StringBuilder query = new StringBuilder();

            for (String fieldName : fieldNames) {
                String fieldValue = vnp_Params.get(fieldName);
                if (fieldValue != null && !fieldValue.isEmpty()) {
                    // Build hash data
                    hashData.append(fieldName).append('=').append(URLEncoder.encode(fieldValue, StandardCharsets.US_ASCII.toString()));
                    // Build query
                    query.append(URLEncoder.encode(fieldName, StandardCharsets.US_ASCII.toString())).append('=')
                            .append(URLEncoder.encode(fieldValue, StandardCharsets.US_ASCII.toString()));

                    if (fieldNames.indexOf(fieldName) < fieldNames.size() - 1) {
                        hashData.append('&');
                        query.append('&');
                    }
                }
            }

            String vnp_SecureHash = hmacSHA512(vnPayConfig.getSecretKey(), hashData.toString());
            query.append("&vnp_SecureHash=").append(vnp_SecureHash);

            return vnPayConfig.getPaymentUrl() + "?" + query;
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Error creating payment URL", e);
        }
    }

    public boolean validatePaymentResponse(Map<String, String> vnpParams) {
        String vnp_SecureHash = vnpParams.get("vnp_SecureHash");
        if (vnp_SecureHash == null) {
            return false;
        }

        // Remove vnp_SecureHash and vnp_SecureHashType from params
        vnpParams.remove("vnp_SecureHash");
        vnpParams.remove("vnp_SecureHashType");

        // Sort params by field name
        List<String> fieldNames = new ArrayList<>(vnpParams.keySet());
        Collections.sort(fieldNames);

        // Build hash data
        StringBuilder hashData = new StringBuilder();
        for (String fieldName : fieldNames) {
            String fieldValue = vnpParams.get(fieldName);
            if (fieldValue != null && !fieldValue.isEmpty()) {
                try {
                    hashData.append(fieldName).append('=').append(URLEncoder.encode(fieldValue, StandardCharsets.US_ASCII.toString()));
                    if (fieldNames.indexOf(fieldName) < fieldNames.size() - 1) {
                        hashData.append('&');
                    }
                } catch (UnsupportedEncodingException e) {
                    throw new RuntimeException("Error validating payment response", e);
                }
            }
        }

        // Calculate secure hash
        String calculatedHash = hmacSHA512(vnPayConfig.getSecretKey(), hashData.toString());

        // Compare calculated hash with received hash
        return calculatedHash.equals(vnp_SecureHash);
    }

    private String hmacSHA512(String key, String data) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA512");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA512");
            hmac.init(secretKeySpec);
            byte[] hmacData = hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hmacData);
        } catch (Exception e) {
            throw new RuntimeException("Error calculating HMAC", e);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}