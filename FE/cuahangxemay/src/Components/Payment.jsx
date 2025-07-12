import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, CreditCard, Info } from "lucide-react";

export default function Payment() {
  const [cartItems, setCartItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [shippingInfo, setShippingInfo] = useState({
    name: "",
    phone: "",
    address: "",
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const navigate = useNavigate();

  // Fetch cart items from API
  useEffect(() => {
    const fetchCartItems = async () => {
      try {
        const token = localStorage.getItem("jwtToken");
        const response = await fetch("http://localhost:8080/api/cart", {
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
        });

        if (!response.ok) {
          throw new Error("Failed to fetch cart items");
        }

        const data = await response.json();

        // ✅ Debug log để xem cấu trúc data
        console.log("Cart items full data:", data);
        if (data.length > 0) {
          console.log("First item structure:", data[0]);
          console.log("Available fields:", Object.keys(data[0]));
        }

        setCartItems(data);
        setLoading(false);
      } catch (error) {
        console.error("Error fetching cart items:", error);
        setLoading(false);
      }
    };

    fetchCartItems();
  }, []);

  // Handle input changes
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setShippingInfo((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  // Calculate total price
  const calculateTotal = () => {
    return cartItems.reduce((total, item) => {
      return total + item.price * item.quantity;
    }, 0);
  };

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();

    if (isSubmitting) return;

    setIsSubmitting(true);

    try {
      const token = localStorage.getItem("jwtToken");
      const response = await fetch("http://localhost:8080/api/payment/create", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          shippingName: shippingInfo.name,
          shippingPhone: shippingInfo.phone,
          shippingAddress: shippingInfo.address,
        }),
      });

      if (!response.ok) {
        throw new Error("Failed to create payment");
      }

      const data = await response.json();

      // Redirect to VNPay payment page
      window.location.href = data.paymentUrl;
    } catch (error) {
      console.error("Error creating payment:", error);
      alert("Không thể tạo thanh toán. Vui lòng thử lại sau.");
      setIsSubmitting(false);
    }
  };

  // Show loading state
  if (loading) {
    return (
      <div className="container mx-auto px-4 py-16 flex justify-center items-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-red-600"></div>
      </div>
    );
  }

  // Show empty cart message
  if (cartItems.length === 0) {
    return (
      <div className="container mx-auto px-4 py-16 text-center">
        <h2 className="text-2xl font-bold text-gray-800 mb-2">
          Giỏ hàng của bạn đang trống
        </h2>
        <p className="text-gray-600 mb-6">
          Không thể tiến hành thanh toán khi giỏ hàng trống
        </p>
        <button
          onClick={() => navigate("/cart")}
          className="inline-flex items-center px-6 py-3 bg-red-600 text-white rounded-md hover:bg-red-700 transition"
        >
          <ArrowLeft size={16} className="mr-2" />
          Quay lại giỏ hàng
        </button>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-2xl font-bold text-gray-800 mb-2">Thanh toán</h1>
      <p className="text-gray-600 mb-6">
        Vui lòng điền thông tin giao hàng để tiếp tục
      </p>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Shipping information form */}
        <div className="lg:col-span-2">
          <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
            <h2 className="text-xl font-bold mb-4 pb-2 border-b border-gray-200">
              Thông tin giao hàng
            </h2>

            <form onSubmit={handleSubmit}>
              <div className="space-y-4">
                <div>
                  <label
                    htmlFor="name"
                    className="block text-sm font-medium text-gray-700 mb-1"
                  >
                    Họ tên người nhận
                  </label>
                  <input
                    type="text"
                    id="name"
                    name="name"
                    value={shippingInfo.name}
                    onChange={handleInputChange}
                    required
                    className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-red-500 focus:border-red-500"
                    placeholder="Nhập họ tên người nhận"
                  />
                </div>

                <div>
                  <label
                    htmlFor="phone"
                    className="block text-sm font-medium text-gray-700 mb-1"
                  >
                    Số điện thoại
                  </label>
                  <input
                    type="tel"
                    id="phone"
                    name="phone"
                    value={shippingInfo.phone}
                    onChange={handleInputChange}
                    required
                    className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-red-500 focus:border-red-500"
                    placeholder="Nhập số điện thoại liên hệ"
                  />
                </div>

                <div>
                  <label
                    htmlFor="address"
                    className="block text-sm font-medium text-gray-700 mb-1"
                  >
                    Địa chỉ giao hàng
                  </label>
                  <textarea
                    id="address"
                    name="address"
                    value={shippingInfo.address}
                    onChange={handleInputChange}
                    required
                    rows="3"
                    className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-red-500 focus:border-red-500"
                    placeholder="Nhập địa chỉ giao hàng chi tiết"
                  ></textarea>
                </div>
              </div>

              <div className="mt-6">
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className={`w-full bg-red-600 hover:bg-red-700 text-white py-3 rounded-md transition flex items-center justify-center ${
                    isSubmitting ? "opacity-70 cursor-not-allowed" : ""
                  }`}
                >
                  {isSubmitting ? (
                    <div className="animate-spin rounded-full h-5 w-5 border-t-2 border-b-2 border-white mr-2"></div>
                  ) : (
                    <CreditCard size={18} className="mr-2" />
                  )}
                  {isSubmitting ? "Đang xử lý..." : "Thanh toán với VNPay"}
                </button>
              </div>
            </form>

            <div className="mt-4 p-3 bg-blue-50 rounded-md">
              <div className="flex">
                <Info
                  size={16}
                  className="text-blue-600 flex-shrink-0 mt-0.5 mr-2"
                />
                <p className="text-xs text-blue-700">
                  Sau khi xác nhận thông tin, bạn sẽ được chuyển đến cổng thanh
                  toán VNPay để hoàn tất giao dịch. Vui lòng không đóng trình
                  duyệt trong quá trình thanh toán.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Order summary */}
        <div className="lg:col-span-1">
          <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 sticky top-4">
            <h2 className="text-xl font-bold mb-4 pb-2 border-b border-gray-200">
              Tóm tắt đơn hàng
            </h2>

            <div className="max-h-60 overflow-y-auto mb-4">
              {cartItems.map((item) => (
                <div
                  key={item.id}
                  className="flex py-2 border-b border-gray-100"
                >
                  <div className="w-16 h-16 bg-gray-100 rounded overflow-hidden mr-3 flex-shrink-0">
                    <img
                      src={
                        item.photo
                          ? `http://localhost:8080/api/files/${item.photo}`
                          : "https://via.placeholder.com/64x64/f3f4f6/9ca3af?text=No+Image"
                      }
                      alt={item.color || "Sản phẩm"}
                      className="w-full h-full object-cover"
                      onError={(e) => {
                        e.target.onerror = null;
                        e.target.src =
                          "https://via.placeholder.com/64x64/f3f4f6/9ca3af?text=No+Image";
                      }}
                    />
                  </div>
                  <div className="flex-1">
                    {/* ✅ Hiển thị cả tên sản phẩm và phiên bản */}
                    <p className="text-sm font-medium text-gray-800">
                      {item.productName || item.name || "Sản phẩm"}
                    </p>
                    <p className="text-xs text-gray-600 mb-1">
                      {item.version && `Phiên bản: ${item.version}`}
                    </p>
                    <p className="text-xs text-gray-500">
                      Màu: {item.color || "N/A"} | SL: {item.quantity || 0}
                    </p>
                    <p className="text-sm font-bold text-red-600">
                      {(item.price || 0).toLocaleString()} VNĐ
                    </p>
                  </div>
                </div>
              ))}
            </div>

            <div className="space-y-3 mb-4">
              <div className="flex justify-between text-gray-600">
                <span>Tạm tính:</span>
                <span>{calculateTotal().toLocaleString()} VNĐ</span>
              </div>

              <div className="flex justify-between text-gray-600">
                <span>Phí đăng ký:</span>
                <span>Theo quy định</span>
              </div>
            </div>

            <div className="border-t border-gray-200 pt-3 mb-6">
              <div className="flex justify-between font-bold">
                <span className="text-lg">Tổng tiền:</span>
                <span className="text-xl text-red-600">
                  {calculateTotal().toLocaleString()} VNĐ
                </span>
              </div>
              <p className="text-xs text-gray-500 mt-1">
                * Giá đã bao gồm VAT, chưa bao gồm phí đăng ký biển số.
              </p>
            </div>

            <button
              onClick={() => navigate("/cart")}
              className="w-full bg-white border border-gray-300 text-gray-700 py-2 rounded-md hover:bg-gray-50 transition flex items-center justify-center"
            >
              <ArrowLeft size={16} className="mr-2" />
              Quay lại giỏ hàng
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
