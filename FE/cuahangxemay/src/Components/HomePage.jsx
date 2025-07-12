import React from "react";

import { useState } from "react";
import {
  ChevronLeft,
  ChevronRight,
  Play,
  Plus,
  Award,
  Activity,
  User,
} from "lucide-react";
import {useTranslation} from "react-i18next";
export default function HondaHomepage() {
  const [currentSlide, setCurrentSlide] = useState(0);
  const { t, i18n } = useTranslation();
  const banners = [
    {
      id: 1,
      image: "honda.jpg",
      title: "HONDA SH150i",
      subtitle: t("honda.subtitle"),
      cta: t("honda.cta"),
    },
    {
      id: 2,
      image: "hondabg1.png",
      title: "WINNER-X",
      subtitle: t("winner.subtitle"),
      cta: t("winner.cta"),
    },
    {
      id: 3,
      image: "hondabg2.jpg",
      title: "ICON e",
      subtitle: t("icon.subtitle"),
      cta: t("icon.cta"),
    },
  ];

  const productCategories = [
    { id: 1, name: "Ô tô", image: "/assets/user/Image/Honda/tayga/AB_125_den.png" },
    { id: 2, name: "Xe máy", image: "/assets/user/Image/Honda/tayga/AB_125_den.png" },
    { id: 3, name: "Xe phân khối lớn", image: "/assets/user/Image/Honda/tayga/AB_125_den.png" },
    { id: 4, name: "Sản phẩm cơ khí", image: "/assets/user/Image/Honda/tayga/AB_125_den.png" },
  ];

  const popularModels = [
    {
      id: 1,
      name: "Honda CR-V",
      price: "Từ 1.109.000.000 VNĐ",
      image: "/assets/user/Image/Honda/tayga/AB_125_den.png",
    },
    {
      id: 2,
      name: "Honda City",
      price: "Từ 559.000.000 VNĐ",
      image: "/assets/user/Image/Honda/tayga/AB_125_den.png",
    },
    {
      id: 3,
      name: "Honda Civic",
      price: "Từ 730.000.000 VNĐ",
      image: "/assets/user/Image/Honda/tayga/AB_125_den.png",
    },
    {
      id: 4,
      name: "Honda HR-V",
      price: "Từ 699.000.000 VNĐ",
      image: "/assets/user/Image/Honda/tayga/AB_125_den.png",
    },
  ];

  const news = [
    {
      id: 1,
      title: "Honda Việt Nam giới thiệu phiên bản mới cho dòng xe CR-V",
      date: "05/05/2025",
      image: "/api/placeholder/350/200",
    },
    {
      id: 2,
      title: "Honda Việt Nam khởi động chuỗi sự kiện lái xe an toàn 2025",
      date: "28/04/2025",
      image: "/api/placeholder/350/200",
    },
    {
      id: 3,
      title: "Honda City đạt doanh số kỷ lục trong tháng 4/2025",
      date: "15/04/2025",
      image: "/api/placeholder/350/200",
    },
  ];

  const nextSlide = () => {
    setCurrentSlide((prev) => (prev === banners.length - 1 ? 0 : prev + 1));
  };

  const prevSlide = () => {
    setCurrentSlide((prev) => (prev === 0 ? banners.length - 1 : prev - 1));
  };

  return (
    <div className="w-full bg-white font-sans">
      {/* Hero Banner Slider */}
      <div className="relative w-full h-96 overflow-hidden">
        {banners.map((banner, index) => (
          <div
            key={banner.id}
            className={`absolute w-full h-full transition-opacity duration-500 ease-in-out ${
              currentSlide === index ? "opacity-100 z-10" : "opacity-0 z-0"
            }`}
          >
            <img
              src={banner.image}
              alt={banner.title}
              className="w-full h-full object-cover"
            />
            <div className="absolute inset-0 bg-gradient-to-r from-black/70 to-transparent flex flex-col justify-center px-16">
              <h2 className="text-4xl font-bold text-white mb-2">
                {banner.title}
              </h2>
              <p className="text-xl text-white mb-6">{banner.subtitle}</p>
              <button className="bg-red-600 hover:bg-red-700 text-white py-2 px-6 rounded-md flex items-center w-fit">
                {banner.cta}
                <ChevronRight className="ml-2 w-4 h-4" />
              </button>
            </div>
          </div>
        ))}

        <button
          onClick={prevSlide}
          className="absolute left-4 top-1/2 -translate-y-1/2 bg-white/30 hover:bg-white/50 rounded-full p-2 z-20"
        >
          <ChevronLeft className="w-6 h-6 text-white" />
        </button>

        <button
          onClick={nextSlide}
          className="absolute right-4 top-1/2 -translate-y-1/2 bg-white/30 hover:bg-white/50 rounded-full p-2 z-20"
        >
          <ChevronRight className="w-6 h-6 text-white" />
        </button>

        <div className="absolute bottom-4 left-1/2 -translate-x-1/2 flex space-x-2 z-20">
          {banners.map((_, index) => (
            <button
              key={index}
              onClick={() => setCurrentSlide(index)}
              className={`w-3 h-3 rounded-full ${
                currentSlide === index ? "bg-red-600" : "bg-white/50"
              }`}
            />
          ))}
        </div>
      </div>

      {/* Product Categories */}
      <div className="container mx-auto py-12 px-4">
        <h2 className="text-3xl font-bold text-gray-800 mb-8 text-center">
          {t("categories.title")}
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {productCategories.map((category) => (
            <div key={category.id} className="group cursor-pointer">
              <div className="relative overflow-hidden rounded-lg mb-3">
                <img
                  src={category.image}
                  alt={category.name}
                  className="w-full h-48 object-cover transition-transform duration-300 group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black/40 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                  <Play className="w-12 h-12 text-white" />
                </div>
              </div>
              <h3 className="text-xl font-bold text-gray-800 text-center">
                {category.name}
              </h3>
            </div>
          ))}
        </div>
      </div>

      {/* Popular Models */}
      <div className="bg-gray-100 py-12">
        <div className="container mx-auto px-4">
          <h2 className="text-3xl font-bold text-gray-800 mb-8 text-center">
            Các mẫu xe phổ biến
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            {popularModels.map((model) => (
              <div
                key={model.id}
                className="bg-white rounded-lg overflow-hidden shadow-md hover:shadow-xl transition-shadow duration-300"
              >
                <div className="relative">
                  <img
                    src={model.image}
                    alt={model.name}
                    className="w-full h-44 object-cover"
                  />
                  <div className="absolute top-2 right-2">
                    <button className="bg-white rounded-full p-1.5 shadow-md hover:bg-gray-100">
                      <Plus className="w-5 h-5 text-red-600" />
                    </button>
                  </div>
                </div>
                <div className="p-4">
                  <h3 className="text-lg font-bold text-gray-800 mb-1">
                    {model.name}
                  </h3>
                  <p className="text-red-600 font-medium">{model.price}</p>
                  <button className="mt-3 w-full bg-gray-800 hover:bg-gray-900 text-white py-2 rounded-md font-medium">
                    Xem chi tiết
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Features */}
      <div className="container mx-auto py-12 px-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div className="flex flex-col items-center text-center">
            <div className="bg-red-100 rounded-full p-4 mb-4">
              <Award className="w-10 h-10 text-red-600" />
            </div>
            <h3 className="text-xl font-bold text-gray-800 mb-2">
              Chất lượng vượt trội
            </h3>
            <p className="text-gray-600">
              Công nghệ tiên tiến và quy trình sản xuất hiện đại tạo nên sản
              phẩm đẳng cấp
            </p>
          </div>

          <div className="flex flex-col items-center text-center">
            <div className="bg-red-100 rounded-full p-4 mb-4">
              <Activity className="w-10 h-10 text-red-600" />
            </div>
            <h3 className="text-xl font-bold text-gray-800 mb-2">
              Hiệu suất bền bỉ
            </h3>
            <p className="text-gray-600">
              Động cơ mạnh mẽ, tiết kiệm nhiên liệu và độ bền cao theo thời gian
            </p>
          </div>

          <div className="flex flex-col items-center text-center">
            <div className="bg-red-100 rounded-full p-4 mb-4">
              <User className="w-10 h-10 text-red-600" />
            </div>
            <h3 className="text-xl font-bold text-gray-800 mb-2">
              Dịch vụ chuyên nghiệp
            </h3>
            <p className="text-gray-600">
              Đội ngũ tư vấn và kỹ thuật viên được đào tạo bài bản, tận tâm với
              khách hàng
            </p>
          </div>
        </div>
      </div>

      {/* News and Events */}
      <div className="bg-gray-100 py-12">
        <div className="container mx-auto px-4">
          <div className="flex justify-between items-center mb-8">
            <h2 className="text-3xl font-bold text-gray-800">
              Tin tức & Sự kiện
            </h2>
            <a
              href="#"
              className="text-red-600 font-medium flex items-center hover:underline"
            >
              Xem tất cả
              <ChevronRight className="w-4 h-4 ml-1" />
            </a>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {news.map((item) => (
              <div
                key={item.id}
                className="bg-white rounded-lg overflow-hidden shadow-md hover:shadow-xl transition-shadow duration-300"
              >
                <img
                  src={item.image}
                  alt={item.title}
                  className="w-full h-48 object-cover"
                />
                <div className="p-4">
                  <p className="text-gray-500 text-sm mb-2">{item.date}</p>
                  <h3 className="text-lg font-bold text-gray-800 mb-3 line-clamp-2">
                    {item.title}
                  </h3>
                  <a
                    href="#"
                    className="text-red-600 font-medium flex items-center hover:underline"
                  >
                    Đọc thêm
                    <ChevronRight className="w-4 h-4 ml-1" />
                  </a>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* CTA Section */}
      <div className="relative">
        <img
          src="/api/placeholder/1600/500"
          alt="Honda Service"
          className="w-full h-80 object-cover"
        />
        <div className="absolute inset-0 bg-black/60 flex flex-col items-center justify-center text-center px-4">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
            Trải nghiệm dịch vụ Honda ngay hôm nay
          </h2>
          <p className="text-white text-lg mb-6 max-w-2xl">
            Đặt lịch kiểm tra và bảo dưỡng xe tại hệ thống đại lý Honda trên
            toàn quốc
          </p>
          <div className="flex flex-col sm:flex-row gap-4">
            <button className="bg-red-600 hover:bg-red-700 text-white py-3 px-8 rounded-md font-medium">
              Đặt lịch dịch vụ
            </button>
            <button className="bg-transparent border-2 border-white hover:bg-white/10 text-white py-3 px-8 rounded-md font-medium">
              Tìm đại lý gần nhất
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
