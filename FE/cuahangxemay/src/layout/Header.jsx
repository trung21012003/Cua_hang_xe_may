import React, { useContext, useState } from "react";
import { Search, User, MapPin, Phone } from "lucide-react";
import { Outlet, useNavigate, useLocation } from "react-router-dom";
import { UserContext } from "../Components/contexts/GetUser.jsx";
import {useTranslation} from "react-i18next";
// Import context để lấy thông tin người dùng

const Header = () => {
  const { isLoggedIn, setIsLoggedIn, setUser, isLoading } =
    useContext(UserContext);
  console.log(isLoggedIn);
  const [showMenu, setShowMenu] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const currentPath = location.pathname;

  const handleLogout = () => {
    localStorage.removeItem("jwtToken");
    setIsLoggedIn(false);
    setUser(null);
    setShowMenu(false);
    navigate("/login");
  };
//import i18n
  const { t, i18n } = useTranslation();

  const changeLanguage = (lng) => {
    i18n.changeLanguage(lng);
  };
  // Hàm kiểm tra đường dẫn hiện tại để áp dụng style active
  const isActive = (path) => {
    if (path === "/") return currentPath === "/";
    return currentPath.startsWith(path);
  };

  // Các định tuyến chính và đường dẫn tương ứng
  const mainNavItems = [
    { name: "Giới thiệu", path: "/about" },
    { name: "Xe máy", path: "/product" },
    { name: "Dịch vụ sau bán hàng", path: "/after-sales" },
    { name: "Đóng góp xã hội", path: "/social" },
    { name: "Motorsports", path: "/motorsports" },
  ];

  // Các định tuyến phụ (sub-header) và đường dẫn tương ứng
  const subNavItems = [
    { name: "Trang chủ", path: "/" },
    { name: "Sản phẩm", path: "/products" },
    { name: "Bảng giá", path: "/prices" },
    { name: "Khuyến mãi", path: "/promotions" },
    { name: "Tư vấn mua xe", path: "/consultation" },
    { name: "Đăng ký lái thử", path: "/test-drive" },
    { name: "Tin tức", path: "/news" },
    { name: "Phụ tùng & phụ kiện", path: "/accessories" },
    { name: "An toàn giao thông", path: "/safety" },
  ];

  return (
    <div className="w-full">
      {/* Top header - contact info */}
      <div className="bg-gray-100 py-2">
        <div className="container mx-auto px-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center space-x-6 text-sm">
              <a
                href="#"
                className="flex items-center text-gray-600 hover:text-red-600"
              >
                <MapPin size={16} className="mr-1" />
                <span>Đại lý</span>
              </a>
              <a
                href="#"
                className="flex items-center text-gray-600 hover:text-red-600"
              >
                <Phone size={16} className="mr-1" />
                <span>Liên hệ</span>
              </a>
            </div>
            <div className="flex items-center space-x-6 text-sm">
              <a href="#" className="text-gray-600 hover:text-red-600">
                Tin tức
              </a>
              <a href="#" className="text-gray-600 hover:text-red-600">
                Tuyển dụng
              </a>
              <div className="flex items-center text-gray-600">
                <button onClick={() => changeLanguage("vi")}
                        className={`px-3 py-1 border-2 rounded text-sm transition duration-200 ${
                            i18n.language === "vi"
                                ? "text-red-600 border-red-600"
                                : "text-gray-700 border-gray-300 hover:text-red-600 hover:border-red-600"
                        }`}
                >VN
                </button>
                <span>|</span>
                <button onClick={() => changeLanguage("en")}
                        className={`px-3 py-1 border-2 rounded text-sm transition duration-200 ${
                            i18n.language === "en"
                                ? "text-red-600 border-red-600"
                                : "text-gray-700 border-gray-300 hover:text-red-600 hover:border-red-600"
                        }`}
                >
                  English
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Main header - logo and navigation */}
      <div className="bg-white shadow-sm">
        <div className="container mx-auto px-4">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <a href="/">
              <div className="flex items-center">
                <div className="flex items-center justify-center bg-red-600 h-10 w-40">
                  <span className="text-white font-bold text-lg">
                    T-MOTOSHOP
                  </span>
                </div>
              </div>
            </a>

            {/* Main Navigation */}
            <nav className="hidden md:flex space-x-8">
              {mainNavItems.map((item) => (
                  <a
                      key={item.path}
                      href={item.path}
                      onClick={(e) => {
                        e.preventDefault();
                        navigate(item.path);
                      }}
                      className={`font-medium border-b-2 py-5 ${
                    isActive(item.path)
                      ? "text-red-600 border-red-600"
                      : "text-gray-700 hover:text-red-600 border-transparent hover:border-red-600"
                  }`}
                >
                    {t(item.name)}
                </a>
              ))}
            </nav>

            <div className="flex items-center space-x-4">
              <div className="header-btn hidden sm:block sm:absolute sm:right-0 sm:mr-16 lg:static lg:mr-0">
                {isLoggedIn ? (
                  <div className="relative">
                    <button
                      className="flex items-center focus:outline-none"
                      onClick={() => setShowMenu(!showMenu)}
                    >
                      <img
                        src="avt.png"
                        alt="Avatar"
                        className="w-10 h-10 rounded-full"
                      />
                    </button>
                    {showMenu && (
                      <div className="absolute right-0 mt-2 w-48 bg-white border border-gray-200 rounded-lg shadow-lg z-50">
                        <a
                          href="/profile"
                          className="block px-4 py-2 text-gray-700 hover:bg-gray-100"
                        >
                          Xem Hồ Sơ
                        </a>
                        <a
                          href="/cart"
                          className="block px-4 py-2 text-gray-700 hover:bg-gray-100"
                        >
                          Giỏ hàng của bạn
                        </a>
                        <a
                          href="/admin"
                          className="block px-4 py-2 text-gray-700 hover:bg-gray-100"
                        >
                          Admin Dashboard
                        </a>
                        <button
                          onClick={handleLogout}
                          className="block w-full text-left px-4 py-2 text-gray-700 hover:bg-gray-100"
                        >
                          Đăng Xuất
                        </button>
                      </div>
                    )}
                  </div>
                ) : (
                  <a
                    className="text-black-600 border border-black px-10 py-3 square-full duration-300 hover:bg-orange-500 hover:text-white"
                    href="/login"
                  >
                    Đăng Nhập
                  </a>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Sub-header - motorcycle specific menu */}
      <div className="bg-gray-50 border-b border-gray-200">
        <div className="container mx-auto px-4">
          <div className="flex overflow-x-auto py-3 space-x-6 no-scrollbar">
            {subNavItems.map((item) => (
              <a
                key={item.path}
                href={item.path}
                onClick={(e) => {
                  e.preventDefault();
                  navigate(item.path);
                }}
                className={`whitespace-nowrap text-sm font-medium ${
                  isActive(item.path)
                    ? "text-red-600"
                    : "text-gray-700 hover:text-red-600"
                }`}
              >
                {t(item.name)}
              </a>
            ))}
          </div>
        </div>
      </div>

      {/* Add Outlet to render child routes */}
      <Outlet />
    </div>
  );
};

export default Header;
