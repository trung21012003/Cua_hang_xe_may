# VNPay Payment Integration

This document provides information about the VNPay payment integration implemented in the Motorbike Shop application.

## Overview

The integration allows customers to pay for their orders using VNPay, a popular payment gateway in Vietnam. After successful payment, the system sends an email with the order details to the customer.

## Features

- VNPay payment integration
- Order management
- Email notifications
- Cart to order conversion

## Configuration

The VNPay configuration is stored in `application.properties`:

```properties
# VNPay Configuration
vnpay.terminal-id=JRNO6CET
vnpay.secret-key=OZ24BZHPIGUSDB49MOGLT7CT33VCHI8E
vnpay.url=https://sandbox.vnpayment.vn/paymentv2/vpcpay.html
vnpay.return-url=http://localhost:8080/api/payment/vnpay-return
```

## Components

### Backend

1. **Entities**:
   - `Order`: Represents an order with shipping and payment information
   - `OrderDetail`: Represents items in an order

2. **Repositories**:
   - `OrderRepository`: Provides data access for orders
   - `OrderDetailRepository`: Provides data access for order details

3. **Services**:
   - `VNPayService`: Handles VNPay payment creation and verification
   - `PaymentService`: Handles order creation and payment processing
   - `EmailService`: Sends email notifications

4. **Controllers**:
   - `PaymentController`: Handles payment requests and callbacks

### Frontend

1. **Payment Page** (`payment.html`):
   - Displays cart items
   - Collects shipping information
   - Initiates payment with VNPay

2. **Payment Result Page** (`payment-result.html`):
   - Displays payment status
   - Shows order ID for successful payments

## Flow

1. User adds products to cart
2. User goes to payment page
3. User enters shipping information and clicks "Pay with VNPay"
4. System creates an order and redirects to VNPay payment page
5. User completes payment on VNPay
6. VNPay redirects back to the application
7. System verifies payment, updates order status, and sends confirmation email
8. User sees payment result page

## Testing

To test the payment integration:

1. Start the application
2. Add products to cart
3. Go to `http://localhost:8080/payment.html`
4. Enter shipping information and click "Pay with VNPay"
5. On the VNPay sandbox page, use the following test card:
   - Card Number: 9704198526191432198
   - Cardholder Name: NGUYEN VAN A
   - Expiry Date: 07/15
   - OTP: 123456
6. Complete the payment
7. You will be redirected back to the application with the payment result
8. Check your email for the order confirmation

## Notes

- This integration uses the VNPay sandbox environment for testing
- In production, you should update the VNPay configuration with your production credentials
- The email service is configured to use Gmail SMTP