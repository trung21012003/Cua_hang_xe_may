package com.example.cua_hang_xe_may.service;

import com.example.cua_hang_xe_may.dto.AccountDTO;
import com.example.cua_hang_xe_may.dto.ProductColorDTO;
import com.example.cua_hang_xe_may.entities.Account;
import com.example.cua_hang_xe_may.entities.Order;
import com.example.cua_hang_xe_may.entities.OrderDetail;
import com.example.cua_hang_xe_may.entities.Productcolor;
import com.example.cua_hang_xe_may.repositories.OrderDetailRepository;
import com.example.cua_hang_xe_may.repositories.OrderRepository;
import com.example.cua_hang_xe_may.repositories.ProductColorRepository;
import jakarta.mail.MessagingException;
import jakarta.transaction.Transactional;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class PaymentService {

    @Autowired
    private CartService cartService;

    @Autowired
    private OrderRepository orderRepository;

    @Autowired
    private OrderDetailRepository orderDetailRepository;

    @Autowired
    private ProductColorRepository productColorRepository;

    @Autowired
    private VNPayService vnPayService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private ModelMapper modelMapper;

    /**
     * Create a new order from cart items
     */
    @Transactional
    public Order createOrderFromCart(AccountDTO accountDTO, String shippingAddress, String shippingPhone, String shippingName) {
        Account user = modelMapper.map(accountDTO, Account.class);
        List<ProductColorDTO> cartItems = cartService.findByUser(accountDTO);

        if (cartItems.isEmpty()) {
            throw new RuntimeException("Cart is empty");
        }

        // Calculate total amount
        double totalAmount = cartItems.stream()
                .mapToDouble(item -> item.getPrice() * item.getQuantity())
                .sum();

        // Create order
        Order order = new Order();
        order.setUser(user);
        order.setOrderDate(Instant.now());
        order.setTotalAmount(totalAmount);
        order.setStatus("PENDING");
        order.setShippingAddress(shippingAddress);
        order.setShippingPhone(shippingPhone);
        order.setShippingName(shippingName);

        // Save order to get ID
        order = orderRepository.save(order);

        // Create order details
        for (ProductColorDTO item : cartItems) {
            Productcolor productColor = productColorRepository.findById(item.getId())
                    .orElseThrow(() -> new RuntimeException("Product color not found"));

            OrderDetail orderDetail = new OrderDetail();
            orderDetail.setOrder(order);
            orderDetail.setProductColorId(item.getId());
            orderDetail.setQuantity(item.getQuantity());
            orderDetail.setPrice(item.getPrice());
            orderDetail.setProductName(productColor.getVersionID().getProduct().getName());
            orderDetail.setProductVersion(productColor.getVersionID().getVersionname());
            orderDetail.setProductColor(productColor.getColor());
            orderDetail.setProductImage(productColor.getPhoto());

            orderDetailRepository.save(orderDetail);
        }

        return order;
    }

    /**
     * Create a payment URL for an order
     */
    public String createPaymentUrl(Order order, String ipAddress) {
        String orderId = order.getId().toString();
        double amount = order.getTotalAmount();
        String orderInfo = "Thanh toan don hang #" + orderId;

        return vnPayService.createPaymentUrl(orderId, amount, orderInfo, ipAddress);
    }

    /**
     * Process payment response from VNPay
     */
    @Transactional
    public boolean processPaymentResponse(Map<String, String> vnpParams) {
        System.out.println("Processing payment response from VNPay");

        // Validate payment response
        if (!vnPayService.validatePaymentResponse(vnpParams)) {
            System.err.println("Invalid payment response from VNPay");
            return false;
        }

        // Get order ID from response
        String orderId = vnpParams.get("vnp_TxnRef");
        String transactionId = vnpParams.get("vnp_TransactionNo");
        String responseCode = vnpParams.get("vnp_ResponseCode");

        System.out.println("Payment response: orderId=" + orderId + ", transactionId=" + transactionId + ", responseCode=" + responseCode);

        // Find order
        Optional<Order> optionalOrder = orderRepository.findById(Integer.parseInt(orderId));
        if (optionalOrder.isEmpty()) {
            System.err.println("Order not found: " + orderId);
            return false;
        }

        Order order = optionalOrder.get();
        System.out.println("Found order: #" + order.getId() + " for user ID: " + (order.getUser() != null ? order.getUser().getId() : "null"));

        // Check if payment is successful
        if ("00".equals(responseCode)) {
            System.out.println("Payment successful for order #" + order.getId());

            // Update order status
            order.setStatus("PAID");
            order.setPaymentMethod("VNPAY");
            order.setTransactionId(transactionId);
            orderRepository.save(order);
            System.out.println("Order status updated to PAID");

            // We don't need to set the orderDetails collection here
            // as it will be loaded lazily when needed
            // and setting it directly can cause orphan deletion issues

            // Send confirmation email
            try {
                System.out.println("Attempting to send confirmation email for order #" + order.getId());

                // Ensure the order is fully loaded with user information
                if (order.getUser() == null) {
                    System.err.println("User is null for order #" + order.getId() + ", trying to reload order");
                    order = orderRepository.findById(order.getId()).orElse(order);
                    if (order.getUser() == null) {
                        System.err.println("User is still null after reloading order #" + order.getId());
                    }
                }

                // Check if user has an email address
                if (order.getUser() != null && order.getUser().getEmail() != null && !order.getUser().getEmail().isEmpty()) {
                    System.out.println("User email found: " + order.getUser().getEmail());
                    sendOrderConfirmationEmail(order);
                } else {
                    System.err.println("Cannot send email: User or email is null for order #" + order.getId());
                    if (order.getUser() != null) {
                        System.err.println("User ID: " + order.getUser().getId() + ", Email: " + order.getUser().getEmail());
                    }
                }
            } catch (MessagingException e) {
                // Log error but don't fail the transaction
                System.err.println("Failed to send confirmation email: " + e.getMessage());
                e.printStackTrace();
            } catch (Exception e) {
                // Log any other unexpected errors
                System.err.println("Unexpected error sending confirmation email: " + e.getMessage());
                e.printStackTrace();
            }

            return true;
        } else {
            // Payment failed
            System.out.println("Payment failed for order #" + order.getId() + " with response code: " + responseCode);
            order.setStatus("PAYMENT_FAILED");
            orderRepository.save(order);
            return false;
        }
    }

    /**
     * Send order confirmation email
     */
    private void sendOrderConfirmationEmail(Order order) throws MessagingException {
        try {
            System.out.println("Starting to send order confirmation email for order #" + order.getId());

            // Check if user and email are available
            if (order.getUser() == null) {
                System.err.println("User is null for order #" + order.getId());
                return;
            }

            String to = order.getUser().getEmail();
            if (to == null || to.isEmpty()) {
                System.err.println("Email address is null or empty for user ID: " + order.getUser().getId());
                return;
            }

            System.out.println("Sending email to: " + to);
            String subject = "Xác nhận đơn hàng #" + order.getId();

            // Explicitly load order details to avoid lazy loading issues
            List<OrderDetail> orderDetails = orderDetailRepository.findByOrder(order);
            System.out.println("Loaded " + orderDetails.size() + " order details for order #" + order.getId());

            StringBuilder content = new StringBuilder();
            content.append("<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>");
            content.append("<h2 style='color: #333;'>Xác nhận đơn hàng</h2>");
            content.append("<p>Cảm ơn bạn đã đặt hàng. Đơn hàng của bạn đã được xác nhận.</p>");
            content.append("<h3>Thông tin đơn hàng #").append(order.getId()).append("</h3>");
            content.append("<p><strong>Ngày đặt hàng:</strong> ").append(order.getOrderDate()).append("</p>");
            content.append("<p><strong>Tổng tiền:</strong> ").append(String.format("%,.0f", order.getTotalAmount())).append(" VND</p>");
            content.append("<p><strong>Phương thức thanh toán:</strong> ").append(order.getPaymentMethod()).append("</p>");
            content.append("<p><strong>Trạng thái:</strong> ").append(order.getStatus()).append("</p>");

            content.append("<h3>Thông tin giao hàng</h3>");
            content.append("<p><strong>Tên:</strong> ").append(order.getShippingName()).append("</p>");
            content.append("<p><strong>Địa chỉ:</strong> ").append(order.getShippingAddress()).append("</p>");
            content.append("<p><strong>Số điện thoại:</strong> ").append(order.getShippingPhone()).append("</p>");

            content.append("<h3>Chi tiết đơn hàng</h3>");
            content.append("<table style='width: 100%; border-collapse: collapse;'>");
            content.append("<tr style='background-color: #f2f2f2;'>");
            content.append("<th style='padding: 8px; text-align: left; border: 1px solid #ddd;'>Sản phẩm</th>");
            content.append("<th style='padding: 8px; text-align: left; border: 1px solid #ddd;'>Phiên bản</th>");
            content.append("<th style='padding: 8px; text-align: left; border: 1px solid #ddd;'>Màu sắc</th>");
            content.append("<th style='padding: 8px; text-align: right; border: 1px solid #ddd;'>Giá</th>");
            content.append("<th style='padding: 8px; text-align: right; border: 1px solid #ddd;'>Số lượng</th>");
            content.append("<th style='padding: 8px; text-align: right; border: 1px solid #ddd;'>Thành tiền</th>");
            content.append("</tr>");

            for (OrderDetail detail : orderDetails) {
                content.append("<tr>");
                content.append("<td style='padding: 8px; text-align: left; border: 1px solid #ddd;'>").append(detail.getProductName()).append("</td>");
                content.append("<td style='padding: 8px; text-align: left; border: 1px solid #ddd;'>").append(detail.getProductVersion()).append("</td>");
                content.append("<td style='padding: 8px; text-align: left; border: 1px solid #ddd;'>").append(detail.getProductColor()).append("</td>");
                content.append("<td style='padding: 8px; text-align: right; border: 1px solid #ddd;'>").append(String.format("%,.0f", detail.getPrice())).append(" VND</td>");
                content.append("<td style='padding: 8px; text-align: right; border: 1px solid #ddd;'>").append(detail.getQuantity()).append("</td>");
                content.append("<td style='padding: 8px; text-align: right; border: 1px solid #ddd;'>").append(String.format("%,.0f", detail.getPrice() * detail.getQuantity())).append(" VND</td>");
                content.append("</tr>");
            }

            content.append("</table>");
            content.append("<p>Cảm ơn bạn đã mua hàng tại cửa hàng của chúng tôi!</p>");
            content.append("</div>");

            System.out.println("Email content prepared, sending email...");
            emailService.sendHtmlEmail(to, subject, content.toString());
            System.out.println("Email sent successfully to " + to);
        } catch (Exception e) {
            System.err.println("Error sending order confirmation email: " + e.getMessage());
            e.printStackTrace();
            // Re-throw as MessagingException to maintain the method signature
            if (e instanceof MessagingException) {
                throw (MessagingException) e;
            } else {
                throw new MessagingException("Error sending email", e);
            }
        }
    }
}
