import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { ShoppingBag, ChevronRight, AlertCircle } from "lucide-react";

export default function Orders() {
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchOrders = async () => {
      try {
        const token = localStorage.getItem("jwtToken");
        const response = await fetch("http://localhost:8080/api/orders", {
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
          },
        });

        if (response.status === 501) {
          // API not implemented yet
          setError("Tính năng đang được phát triển. Vui lòng quay lại sau.");
          setLoading(false);
          return;
        }

        if (!response.ok) {
          throw new Error("Failed to fetch orders");
        }

        const data = await response.json();
        setOrders(data);
        setLoading(false);
      } catch (error) {
        console.error("Error fetching orders:", error);
        setError("Không thể tải danh sách đơn hàng. Vui lòng thử lại sau.");
        setLoading(false);
      }
    };

    fetchOrders();
  }, []);

  // Show loading state
  if (loading) {
    return (
      <div className="container mx-auto px-4 py-16 flex justify-center items-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-red-600"></div>
      </div>
    );
  }

  // Show error message
  if (error) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-2xl font-bold text-gray-800 mb-6">Đơn hàng của tôi</h1>
          
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 flex items-start">
            <AlertCircle className="text-yellow-500 mr-3 mt-0.5 flex-shrink-0" size={20} />
            <div>
              <p className="text-yellow-700">{error}</p>
              <p className="text-yellow-600 text-sm mt-1">
                Chúng tôi đang phát triển tính năng xem lịch sử đơn hàng. 
                Bạn có thể quay lại sau hoặc liên hệ với chúng tôi để biết thông tin về đơn hàng của bạn.
              </p>
            </div>
          </div>
          
          <div className="mt-6">
            <Link 
              to="/" 
              className="inline-flex items-center text-red-600 hover:text-red-800"
            >
              <ShoppingBag size={16} className="mr-2" />
              Tiếp tục mua sắm
            </Link>
          </div>
        </div>
      </div>
    );
  }

  // Show empty orders message
  if (orders.length === 0) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-2xl font-bold text-gray-800 mb-6">Đơn hàng của tôi</h1>
          
          <div className="bg-white p-8 rounded-lg shadow-sm border border-gray-200 text-center">
            <ShoppingBag size={48} className="mx-auto text-gray-300 mb-4" />
            <h2 className="text-xl font-bold text-gray-800 mb-2">
              Bạn chưa có đơn hàng nào
            </h2>
            <p className="text-gray-600 mb-6">
              Hãy khám phá các sản phẩm của chúng tôi và đặt hàng ngay
            </p>
            <Link
              to="/product"
              className="inline-flex items-center px-6 py-3 bg-red-600 text-white rounded-md hover:bg-red-700 transition"
            >
              Xem danh sách xe máy
              <ChevronRight size={16} className="ml-2" />
            </Link>
          </div>
        </div>
      </div>
    );
  }

  // Show orders list (this part will be implemented when the API is ready)
  return (
    <div className="container mx-auto px-4 py-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-2xl font-bold text-gray-800 mb-6">Đơn hàng của tôi</h1>
        
        <div className="space-y-4">
          {orders.map((order) => (
            <div 
              key={order.id} 
              className="bg-white p-4 rounded-lg shadow-sm border border-gray-200"
            >
              <div className="flex justify-between items-center mb-3">
                <div>
                  <span className="text-sm text-gray-500">Mã đơn hàng:</span>
                  <span className="font-medium ml-2">#{order.id}</span>
                </div>
                <div className="text-sm">
                  <span className="text-gray-500">Ngày đặt:</span>
                  <span className="ml-2">
                    {new Date(order.orderDate).toLocaleDateString("vi-VN")}
                  </span>
                </div>
              </div>
              
              <div className="flex justify-between items-center mb-3">
                <div className="text-sm">
                  <span className="text-gray-500">Trạng thái:</span>
                  <span className="ml-2 px-2 py-1 bg-green-100 text-green-800 rounded-full text-xs font-medium">
                    {order.status}
                  </span>
                </div>
                <div>
                  <span className="text-gray-500">Tổng tiền:</span>
                  <span className="font-bold text-red-600 ml-2">
                    {order.totalAmount.toLocaleString()} VNĐ
                  </span>
                </div>
              </div>
              
              <Link
                to={`/account/orders/${order.id}`}
                className="text-blue-600 text-sm hover:underline flex items-center mt-2"
              >
                Xem chi tiết
                <ChevronRight size={14} className="ml-1" />
              </Link>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}