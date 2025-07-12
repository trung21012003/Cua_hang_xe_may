import React, { useState, useEffect } from "react";
import { Search, Filter, ArrowRight } from "lucide-react";
import {Link} from "react-router-dom"
import axios from "axios";
import ScrollRestoration from "./ScrollRestoration.jsx";

export default function ScooterListingPage() {
  const [activeTab, setActiveTab] = useState("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Tabs for filtering motorcycles by category
  const tabs = [
    { id: "all", label: "Tất cả", isActive: true },
    { id: "xe ga", label: "Xe tay ga", isActive: false },
    { id: "xe số", label: "Xe số", isActive: false },
    { id: "xe côn tay", label: "Xe côn tay", isActive: false },
    { id: "xe phân khối lớn", label: "Xe phân khối lớn", isActive: false },
    { id: "xe điện", label: "Xe điện", isActive: false },
  ];

  // Thiết lập instance Axios với cấu hình cơ bản
  const api = axios.create({
    baseURL: "http://localhost:8080/api",
    timeout: 10000,
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
  });

  // Fetch products from API using Axios
  useEffect(() => {
    const fetchProducts = async () => {
      try {
        setLoading(true);
        const response = await api.get("/products/public");
        setProducts(response.data);
        setError(null);
      } catch (err) {
        console.error("Error fetching products:", err);
        const errorMsg = err.response
          ? `Lỗi: ${err.response.status} - ${err.response.statusText}`
          : "Không thể tải dữ liệu sản phẩm. Vui lòng thử lại sau.";
        setError(errorMsg);
      } finally {
        setLoading(false);
      }
    };

    fetchProducts();
  }, []);
  const handleTabClick = (tabId) => {
    setActiveTab(tabId);
  };

  // Format price to Vietnamese currency format
  const formatPrice = (price) => {
    return new Intl.NumberFormat("vi-VN").format(price) + " VND";
  };

  // Filter products based on active tab and search term
  const filteredProducts = products.filter((product) => {
    const matchesTab =
      activeTab === "all" ||
      product.motolineName?.toLowerCase() === activeTab.toLowerCase();
    const matchesSearch = product.name
      ?.toLowerCase()
      .includes(searchTerm.toLowerCase());
    return matchesTab && matchesSearch;
  });

  return (
    <>
      <ScrollRestoration />
      <div className="container mx-auto px-4 pb-12">
        {/* Navigation Tabs */}
        <div className="w-full border-b border-gray-200 mb-8">
          <div className="flex overflow-x-auto no-scrollbar">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                className={`px-4 py-4 text-sm font-medium whitespace-nowrap ${
                  activeTab === tab.id
                    ? "text-red-600 border-b-2 border-red-600"
                    : "text-gray-700 hover:text-red-500"
                }`}
                onClick={() => handleTabClick(tab.id)}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Search and Filter Section */}
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between mb-8 gap-4">
          <div className="relative w-full md:w-64">
            <input
              type="text"
              placeholder="Nhập tên loại xe"
              className="border border-gray-300 rounded-md pl-4 pr-10 py-2 w-full"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
            <div className="absolute right-3 top-2.5">
              <Search size={20} className="text-gray-400" />
            </div>
          </div>

          <div className="flex items-center gap-2">
            <div className="p-3 rounded-full bg-red-50 flex items-center justify-center">
              <Filter size={20} className="text-red-500" />
            </div>
            <div>
              <div className="text-gray-600 text-sm">Kết quả:</div>
              <div className="font-medium">
                {filteredProducts.length} sản phẩm
              </div>
            </div>
          </div>
        </div>

        {/* Buttons */}
        <div className="flex justify-end mb-8 gap-4">
          <button className="border border-red-600 text-red-600 px-4 py-2 rounded flex items-center gap-2 text-sm font-medium">
            BẢNG GIÁ SẢN PHẨM <ArrowRight size={16} />
          </button>
          <button className="border border-red-600 text-red-600 px-4 py-2 rounded flex items-center gap-2 text-sm font-medium">
            SO SÁNH SẢN PHẨM <ArrowRight size={16} />
          </button>
        </div>

        {/* Loading and Error States */}
        {loading && (
          <div className="text-center py-8">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto"></div>
            <p className="mt-4 text-gray-600">Đang tải dữ liệu...</p>
          </div>
        )}

        {error && (
          <div className="text-center py-8 text-red-500">
            <p>{error}</p>
          </div>
        )}

        {/* Product Grid */}
        {!loading && !error && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            {filteredProducts.length > 0 ? (
              filteredProducts.map((product) => (
                  <Link  key={product.id} to={`/productdetail/${product.id}`} className="block">
                <div
                  className="border border-gray-200 rounded-lg overflow-hidden hover:shadow-md transition-shadow"
                >
                  {/*Product*/}
                  <div className="p-4 text-center">
                    <h3 className="text-xl font-bold mb-4">{product.name}</h3>
                    <img
                      src={
                        product.avatar
                          ? `http://localhost:8080/api/files/${product.avatar}`
                          : "/api/placeholder/300/200"
                      }
                      alt={product.name}
                      className="w-full h-48 object-contain mb-4"
                    />
                    <div className="flex flex-col gap-2">
                      <div className="flex items-center justify-center gap-2">
                        <span className="text-gray-600">Giá từ:</span>
                        <span className="font-bold">
                          {formatPrice(product.price)}
                        </span>
                      </div>
                      <div className="text-sm text-gray-600">
                        {product.description}
                      </div>
                      <div className="text-sm text-gray-600">
                        Hãng: {product.brandName}
                      </div>
                    </div>
                  </div>
                </div>
                  </Link>
              ))
            ) : (
              <div className="col-span-full text-center text-gray-600 py-8">
                Không tìm thấy sản phẩm phù hợp
              </div>
            )}
          </div>
        )}

        {/* Scroll to top button */}
        <button
          className="fixed bottom-8 right-8 bg-gray-800 text-white p-3 rounded-full shadow-lg"
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
        >
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M18 15l-6-6-6 6" />
          </svg>
        </button>
      </div>
    </>
  );
}
