import React, { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { CheckCircle, XCircle, ArrowRight, Home } from "lucide-react";

export default function PaymentResult() {
  const [orderDetails, setOrderDetails] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    // Parse URL parameters
    const params = new URLSearchParams(location.search);
    const success = params.get("success") === "true";
    const orderId = params.get("orderId");

    if (success && orderId) {
      // Fetch order details if payment was successful
      fetchOrderDetails(orderId);
    } else {
      // Just set loading to false if payment failed
      setLoading(false);
    }
  }, [location]);

  const fetchOrderDetails = async (orderId) => {
    try {
      const token = localStorage.getItem("jwtToken");
      const response = await fetch(`http://localhost:8080/api/orders/${orderId}`, {
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setOrderDetails(data);
      }
    } catch (error) {
      console.error("Error fetching order details:", error);
    } finally {
      setLoading(false);
    }
  };

  // Check if payment was successful
  const isSuccess = new URLSearchParams(location.search).get("success") === "true";

  // Show loading state
  if (loading) {
    return (
      <div className="container mx-auto px-4 py-16 flex justify-center items-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-red-600"></div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className={`max-w-2xl mx-auto bg-white p-8 rounded-lg shadow-sm border ${
        isSuccess ? "border-green-200" : "border-red-200"
      }`}>
        <div className="text-center mb-6">
          {isSuccess ? (
            <CheckCircle size={64} className="mx-auto text-green-500 mb-4" />
          ) : (
            <XCircle size={64} className="mx-auto text-red-500 mb-4" />
          )}

          <h1 className="text-2xl font-bold text-gray-800 mb-2">
            {isSuccess ? "Thanh toán thành công!" : "Thanh toán thất bại!"}
          </h1>

          <p className="text-gray-600">
            {isSuccess 
              ? "Cảm ơn bạn đã mua hàng. Đơn hàng của bạn đã được xác nhận và đang được xử lý."
              : "Đã xảy ra lỗi trong quá trình thanh toán. Vui lòng thử lại hoặc liên hệ với chúng tôi để được hỗ trợ."}
          </p>
        </div>

        {isSuccess && orderDetails && (
          <div className="border-t border-gray-200 pt-6 mb-6">
            <h2 className="text-lg font-bold mb-4">Chi tiết đơn hàng</h2>

            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-gray-600">Mã đơn hàng:</span>
                <span className="font-medium">{orderDetails.id}</span>
              </div>

              <div className="flex justify-between">
                <span className="text-gray-600">Ngày đặt hàng:</span>
                <span className="font-medium">
                  {new Date(orderDetails.orderDate).toLocaleString("vi-VN")}
                </span>
              </div>

              <div className="flex justify-between">
                <span className="text-gray-600">Tổng tiền:</span>
                <span className="font-medium text-red-600">
                  {orderDetails.totalAmount.toLocaleString()} VNĐ
                </span>
              </div>

              <div className="flex justify-between">
                <span className="text-gray-600">Phương thức thanh toán:</span>
                <span className="font-medium">VNPay</span>
              </div>

              <div className="flex justify-between">
                <span className="text-gray-600">Trạng thái:</span>
                <span className="font-medium text-green-600">Đã thanh toán</span>
              </div>
            </div>

            <div className="mt-4 p-3 bg-blue-50 rounded-md">
              <p className="text-sm text-blue-700">
                Chúng tôi đã gửi email xác nhận đơn hàng đến địa chỉ email của bạn. 
                Vui lòng kiểm tra hộp thư để xem chi tiết đơn hàng.
              </p>
            </div>
          </div>
        )}

        <div className="flex flex-col sm:flex-row justify-center gap-4 mt-6">
          <button
            onClick={() => navigate("/")}
            className="px-6 py-3 bg-gray-100 text-gray-800 rounded-md hover:bg-gray-200 transition flex items-center justify-center"
          >
            <Home size={18} className="mr-2" />
            Trang chủ
          </button>

          {isSuccess ? (
            <button
              onClick={() => navigate("/account/orders")}
              className="px-6 py-3 bg-red-600 text-white rounded-md hover:bg-red-700 transition flex items-center justify-center"
            >
              Xem đơn hàng của tôi
              <ArrowRight size={18} className="ml-2" />
            </button>
          ) : (
            <button
              onClick={() => navigate("/cart")}
              className="px-6 py-3 bg-red-600 text-white rounded-md hover:bg-red-700 transition flex items-center justify-center"
            >
              Quay lại giỏ hàng
              <ArrowRight size={18} className="ml-2" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
