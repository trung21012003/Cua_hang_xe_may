import React, { useEffect, useState } from "react";
import axios from "axios";
import { useParams, Link, useSearchParams } from "react-router-dom";
import {
  ShoppingCart,
  Heart,
  Share2,
  ArrowLeft,
  Calendar,
  Wrench,
  CheckCircle2,
  Info,
  CircleDollarSign,
  Star,
  StarOff,
} from "lucide-react";

export default function ProductDetail() {
  const { id } = useParams();
  const [searchParams] = useSearchParams();
  const versionParam = searchParams.get("version");
  const colorParam = searchParams.get("color");
  const [product, setProduct] = useState(null);
  const [versionColors, setVersionColors] = useState([]);
  const [selectedColor, setSelectedColor] = useState(null);
  const [selectedVersion, setSelectedVersion] = useState(null);
  const [quantity, setQuantity] = useState(1);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("specs");

  // States cho comments/reviews
  const [comments, setComments] = useState([]);
  const [ratingStats, setRatingStats] = useState({
    averageRating: 0,
    totalReviews: 0,
    ratingDistribution: {},
  });
  const [canUserReview, setCanUserReview] = useState({
    canReview: false,
    hasPurchased: false,
    hasReviewed: false,
  });
  const [newReview, setNewReview] = useState({
    rating: 0,
    content: "",
  });
  const [submittingReview, setSubmittingReview] = useState(false);

  //anh thay doi theo mau
  const [selectedImage, setSelectedImage] = useState(null);

  // Functions cho comments/reviews
  const fetchComments = async () => {
    try {
      console.log("Fetching comments for product:", id);
      const response = await axios.get(
        `http://localhost:8080/api/comments/public/product/${id}`
      );
      console.log("Comments response:", response.data);
      setComments(response.data);
    } catch (error) {
      console.error("Error fetching comments:", error);
      console.error("Error details:", error.response?.data);
    }
  };

  const fetchRatingStats = async () => {
    try {
      console.log("Fetching rating stats for product:", id);
      const response = await axios.get(
        `http://localhost:8080/api/comments/public/product/${id}/rating-stats`
      );
      console.log("Rating stats response:", response.data);
      setRatingStats(response.data);
    } catch (error) {
      console.error("Error fetching rating stats:", error);
      console.error("Error details:", error.response?.data);
    }
  };

  const checkCanUserReview = async () => {
    const token = localStorage.getItem("jwtToken");
    if (!token) {
      console.log("No token found, user cannot review");
      setCanUserReview({
        canReview: false,
        hasPurchased: false,
        hasReviewed: false,
      });
      return;
    }

    try {
      console.log("Checking if user can review product:", id);
      const response = await axios.get(
        `http://localhost:8080/api/comments/can-review/product/${id}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );
      console.log("Can review response:", response.data);
      setCanUserReview(response.data);
    } catch (error) {
      console.error("Error checking review permission:", error);
      console.error("Error details:", error.response?.data);
    }
  };

  const submitReview = async () => {
    if (newReview.rating === 0) {
      alert("Vui lòng chọn số sao đánh giá");
      return;
    }
    if (newReview.content.trim() === "") {
      alert("Vui lòng nhập nội dung đánh giá");
      return;
    }

    const token = localStorage.getItem("jwtToken");
    if (!token) {
      alert("Vui lòng đăng nhập để đánh giá");
      return;
    }

    setSubmittingReview(true);
    try {
      await axios.post(
        "http://localhost:8080/api/comments",
        {
          productId: parseInt(id),
          content: newReview.content.trim(),
          rating: newReview.rating,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      alert("Đánh giá của bạn đã được gửi thành công!");
      setNewReview({ rating: 0, content: "" });

      // Refresh data
      fetchComments();
      fetchRatingStats();
      checkCanUserReview();
    } catch (error) {
      console.error("Error submitting review:", error);
      if (error.response?.data?.message) {
        alert(error.response.data.message);
      } else {
        alert("Có lỗi xảy ra khi gửi đánh giá");
      }
    } finally {
      setSubmittingReview(false);
    }
  };

  const renderStars = (
    rating,
    size = "h-4 w-4",
    interactive = false,
    onStarClick = null
  ) => {
    return (
      <div className="flex">
        {[1, 2, 3, 4, 5].map((star) => (
          <Star
            key={star}
            size={size === "h-4 w-4" ? 16 : size === "h-5 w-5" ? 20 : 24}
            className={`${size} ${
              star <= rating ? "text-yellow-400 fill-current" : "text-gray-300"
            } ${interactive ? "cursor-pointer hover:text-yellow-400" : ""}`}
            onClick={
              interactive && onStarClick ? () => onStarClick(star) : undefined
            }
          />
        ))}
      </div>
    );
  };

  useEffect(() => {
    async function fetchProductDetail() {
      try {
        setLoading(true);
        const res = await axios.get(`http://localhost:8080/api/products/public/${id}`);
        console.log("Dữ liệu API:", res.data);
        setProduct(res.data.product);
        setVersionColors(res.data.product.versionColors);

        // Thiết lập phiên bản và màu mặc định
        //   if (res.data.product.versionColors.length > 0) {
        //       const firstVersion = res.data.product.versionColors[0];
        //       setSelectedVersion(firstVersion);
        //
        //       const firstColor = firstVersion.colors?.find(c => c.quantity > 0) || firstVersion.colors[0] || null;
        //       setSelectedColor(firstColor);
        //   }
        let selectedVer = null;
        let selectedCol = null;

        if (versionParam) {
          selectedVer = res.data.product.versionColors.find(
            (v) => v.versionName === versionParam
          );
        }

        if (!selectedVer) {
          selectedVer = res.data.product.versionColors[0];
        }

        if (colorParam && selectedVer) {
          selectedCol = selectedVer.colors.find(
            (c) => c.color.toLowerCase() === colorParam.toLowerCase()
          );
        }

        if (!selectedCol && selectedVer) {
          selectedCol =
            selectedVer.colors?.find((c) => c.quantity > 0) ||
            selectedVer.colors[0];
        }

        setSelectedVersion(selectedVer);
        setSelectedColor(selectedCol);

        setLoading(false);
      } catch (err) {
        console.error(err);
        setLoading(false);
      }
    }
    fetchProductDetail();
  }, [id]);

  // Fetch comments and related data when component loads
  useEffect(() => {
    if (id) {
      fetchComments();
      fetchRatingStats();
      checkCanUserReview();
    }
  }, [id]);

  // Hàm xử lý khi thay đổi phiên bản
  const handleVersionChange = (version) => {
    setSelectedVersion(version);
    setSelectedColor(version.colors[0]);
  };

  // Hàm xử lý thêm vào giỏ hàng
  const handleAddToCart = async () => {
    if (!selectedColor || !selectedVersion || !product) return;

    try {
      const token = localStorage.getItem("jwtToken");

      if (!token) {
        alert("Bạn chưa đăng nhập hoặc phiên đăng nhập đã hết hạn");
        return;
      }

      const payload = {
        id: selectedColor.id,
        color: selectedColor.color,
        price: selectedColor.price,
        quantity: quantity,
        photo: selectedColor.photo,
      };

      const res = await axios.post(
        "http://localhost:8080/api/cart/add",
        payload,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      alert("Sản phẩm đã được thêm vào giỏ hàng!");
      console.log("Cart response:", res.data);
    } catch (error) {
      console.error("Lỗi thêm vào giỏ hàng:", error);
      alert("Không thể thêm vào giỏ hàng");
    }
  };

  // Hàm xử lý đặt lịch xem xe
  const handleBookTestRide = () => {
    console.log("Đặt lịch lái thử xe:", {
      product: product.name,
      version: selectedVersion?.versionName,
      color: selectedColor?.color,
    });
  };

  // Hiển thị trạng thái đang tải
  if (loading) {
    return (
      <div className="flex justify-center items-center min-h-[500px]">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-red-600"></div>
      </div>
    );
  }

  // Hiển thị thông báo lỗi nếu không tìm thấy sản phẩm
  if (!product || !selectedColor) {
    return (
      <div className="container mx-auto px-4 py-16 text-center">
        <h2 className="text-2xl font-bold text-gray-800">
          Không tìm thấy sản phẩm
        </h2>
        <p className="mt-2 text-gray-600">
          Sản phẩm không tồn tại hoặc đã bị xóa
        </p>
        <Link
          to="/product"
          className="mt-4 inline-flex items-center text-red-600 hover:text-red-700"
        >
          <ArrowLeft size={16} className="mr-1" />
          Quay lại trang sản phẩm
        </Link>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Đường dẫn điều hướng */}
      <div className="text-sm text-gray-500 mb-6">
        <Link to="/" className="hover:text-red-600">
          Trang chủ
        </Link>{" "}
        /
        <Link to="/product" className="hover:text-red-600">
          {" "}
          Xe máy
        </Link>{" "}
        /{" "}
        <Link
          to={`/product?brand=${product.brandName}`}
          className="hover:text-red-600"
        >
          {product.brandName}
        </Link>{" "}
        /<span className="text-gray-800"> {product.name}</span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Phần hình ảnh bên trái */}
        <div className="bg-gray-50 rounded-lg overflow-hidden p-4">
          <div className="relative pb-4">
            <img
              src={`http://localhost:8080/api/files/${
                selectedImage || product.avatar
              }`}
              alt={product.name}
              className="w-full h-auto object-contain rounded-lg"
              style={{ maxHeight: "400px" }}
            />

            {/* Huy hiệu khuyến mãi và thông tin nổi bật */}
            <div className="absolute top-4 left-4 right-4 flex justify-between">
              {product.discount > 0 && (
                <div className="bg-red-600 text-white px-3 py-1 rounded-full text-sm font-medium">
                  Giảm {product.discount}%
                </div>
              )}

              {product.isNew && (
                <div className="bg-blue-600 text-white px-3 py-1 rounded-full text-sm font-medium ml-2">
                  Mẫu mới 2024
                </div>
              )}
            </div>
          </div>
          {/* Thêm thông tin công nghệ nổi bật */}
          <div className="mt-6 p-4 bg-gray-100 rounded-lg">
            <h3 className="text-sm font-medium text-gray-900 mb-2">
              Công nghệ nổi bật
            </h3>
            <div className="grid grid-cols-2 gap-3">
              <div className="flex items-start">
                <CheckCircle2
                  size={16}
                  className="text-green-600 mr-1 mt-0.5"
                />
                <span className="text-sm text-gray-600">
                  Động cơ {product.category === "xe số" ? "eSP" : "BlueCore"}
                </span>
              </div>
              <div className="flex items-start">
                <CheckCircle2
                  size={16}
                  className="text-green-600 mr-1 mt-0.5"
                />
                <span className="text-sm text-gray-600">
                  Phanh{" "}
                  {product.category === "xe phân khối lớn" ? "ABS" : "CBS"}
                </span>
              </div>
              <div className="flex items-start">
                <CheckCircle2
                  size={16}
                  className="text-green-600 mr-1 mt-0.5"
                />
                <span className="text-sm text-gray-600">
                  Hệ thống phun xăng điện tử
                </span>
              </div>
              <div className="flex items-start">
                <CheckCircle2
                  size={16}
                  className="text-green-600 mr-1 mt-0.5"
                />
                <span className="text-sm text-gray-600">
                  Smart Key{" "}
                  {product.category === "xe ga" ? "tiêu chuẩn" : "tùy chọn"}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Phần thông tin sản phẩm bên phải */}
        <div className="flex flex-col">
          {/* Tên và đánh giá */}
          <div className="flex flex-col md:flex-row md:items-center md:justify-between">
            <h1 className="text-3xl font-bold text-gray-800">{product.name}</h1>
            <div className="flex items-center mt-2 md:mt-0">
              <div className="px-3 py-1 rounded-full bg-blue-100 text-blue-800 text-xs font-medium">
                {product.category}
              </div>
            </div>
          </div>

          <div className="flex items-center mt-2">
            <div className="flex">
              {renderStars(
                Math.round(ratingStats.averageRating || 0),
                "h-4 w-4"
              )}
            </div>
            <span className="ml-2 text-gray-600 text-sm">
              Có {ratingStats.totalReviews} đánh giá
            </span>
            <span className="mx-2 text-gray-300">|</span>
            <span className="text-green-600 text-sm">
              Có sẵn {selectedColor?.quantity} xe
            </span>
          </div>

          {/* Giá và tính năng */}
          <div className="mt-6 p-4 bg-gray-50 rounded-lg">
            <div className="flex items-baseline">
              <h2 className="text-3xl font-bold text-red-600">
                {selectedColor?.price.toLocaleString()} VNĐ
              </h2>
              {product.discount > 0 && (
                <span className="ml-3 text-gray-500 line-through text-lg">
                  {(
                    (selectedColor?.price * 100) /
                    (100 - product.discount)
                  ).toLocaleString()}{" "}
                  VNĐ
                </span>
              )}
            </div>
            <p className="text-sm text-gray-500 mt-2">
              Giá đã bao gồm VAT (chưa bao gồm phí đăng ký biển số)
            </p>

            <div className="mt-3 flex flex-wrap gap-2">
              <div className="bg-green-100 text-green-800 px-2 py-1 rounded text-xs font-medium flex items-center">
                <CircleDollarSign size={14} className="mr-1" /> Trả góp 0%
              </div>
              <div className="bg-blue-100 text-blue-800 px-2 py-1 rounded text-xs font-medium flex items-center">
                <Info size={14} className="mr-1" /> Bảo hành 3 năm
              </div>
            </div>
          </div>

          {/* Chọn phiên bản */}
          <div className="mt-6">
            <h3 className="text-sm font-medium text-gray-900">Phiên bản</h3>
            <div className="flex flex-wrap gap-2 mt-2">
              {versionColors.map((version, vi) => (
                <button
                  key={vi}
                  type="button"
                  className={`px-4 py-2 text-sm rounded-md ${
                    selectedVersion?.versionName === version.versionName
                      ? "bg-red-600 text-white"
                      : "bg-gray-100 text-gray-800 hover:bg-gray-200"
                  }`}
                  onClick={() => handleVersionChange(version)}
                >
                  {version.versionName}
                </button>
              ))}
            </div>
          </div>

          {/* Chọn màu sắc */}
          <div className="mt-6">
            <h3 className="text-sm font-medium text-gray-900">Màu sắc</h3>
            <div className="flex flex-wrap gap-4 mt-3">
              {selectedVersion?.colors.map((color, ci) => (
                <div
                  key={ci}
                  className={`flex flex-col items-center cursor-pointer ${
                    selectedColor?.color === color.color
                      ? "opacity-100"
                      : "opacity-70"
                  }`}
                  onClick={() => {
                    setSelectedColor(color);
                    setSelectedImage(color.photo || product.avatar);
                  }}
                >
                  <div
                    className={`w-14 h-14 rounded-full border-2 ${
                      selectedColor?.color === color.color
                        ? "border-red-600"
                        : "border-gray-300"
                    }`}
                  >
                    <img
                      src={`http://localhost:8080/api/files/${
                        color.photo || product.avatar
                      }`}
                      alt={color.color}
                      className="w-full h-full rounded-full object-cover m-0.5 cursor-pointer"
                      onClick={() => {
                        setSelectedColor(color);
                        setSelectedImage(color.photo || product.avatar);
                      }}
                    />
                  </div>
                  <span className="mt-1 text-xs text-gray-700">
                    {color.color}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Chọn số lượng */}
          <div className="mt-6">
            <h3 className="text-sm font-medium text-gray-900">Số lượng</h3>
            <div className="flex items-center mt-2">
              <button
                onClick={() => setQuantity(Math.max(1, quantity - 1))}
                className="w-10 h-10 flex items-center justify-center rounded-l border border-gray-300 bg-gray-50 text-gray-600 hover:bg-gray-100"
              >
                -
              </button>
              <input
                type="number"
                value={quantity}
                onChange={(e) =>
                  setQuantity(Math.max(1, parseInt(e.target.value) || 1))
                }
                min="1"
                max={selectedColor?.quantity || 1}
                className="w-14 h-10 text-center border-y border-gray-300"
              />
              <button
                onClick={() =>
                  setQuantity(
                    Math.min(selectedColor?.quantity || 1, quantity + 1)
                  )
                }
                className="w-10 h-10 flex items-center justify-center rounded-r border border-gray-300 bg-gray-50 text-gray-600 hover:bg-gray-100"
              >
                +
              </button>
            </div>
          </div>

          {/* Nút hành động */}
          <div className="mt-8 flex flex-col sm:flex-row gap-3">
            <button
              onClick={handleAddToCart}
              className="bg-red-600 text-white py-3 px-6 rounded-md hover:bg-red-700 flex items-center justify-center text-sm font-medium w-full sm:flex-1"
            >
              <ShoppingCart size={18} className="mr-2" />
              Thêm vào giỏ hàng
            </button>

            <button
              onClick={handleBookTestRide}
              className="bg-blue-600 text-white py-3 px-6 rounded-md hover:bg-blue-700 flex items-center justify-center text-sm font-medium w-full sm:flex-1"
            >
              <Calendar size={18} className="mr-2" />
              Đặt lịch lái thử
            </button>
          </div>

          <div className="mt-3 flex gap-3">
            <button className="border border-gray-300 rounded-md flex items-center justify-center hover:bg-gray-50 py-2 px-4 text-sm w-full sm:flex-1">
              <Heart size={18} className="text-gray-600 mr-2" />
              <span>Yêu thích</span>
            </button>

            <button className="border border-gray-300 rounded-md flex items-center justify-center hover:bg-gray-50 py-2 px-4 text-sm w-full sm:flex-1">
              <Share2 size={18} className="text-gray-600 mr-2" />
              <span>Chia sẻ</span>
            </button>
          </div>

          {/* Thông tin giao hàng */}
          <div className="mt-8 p-4 bg-gray-50 rounded-md">
            <h3 className="font-medium text-gray-900 mb-3">
              Chính sách mua hàng
            </h3>
            <div className="flex items-start mb-3">
              <svg
                className="w-5 h-5 text-green-500 mt-0.5 mr-2 flex-shrink-0"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M5 13l4 4L19 7"
                ></path>
              </svg>
              <span className="text-gray-600 text-sm">
                Hỗ trợ đăng ký, đăng kiểm xe
              </span>
            </div>
            <div className="flex items-start mb-3">
              <svg
                className="w-5 h-5 text-green-500 mt-0.5 mr-2 flex-shrink-0"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M5 13l4 4L19 7"
                ></path>
              </svg>
              <span className="text-gray-600 text-sm">
                Bảo hành chính hãng 3 năm hoặc 30.000 km
              </span>
            </div>
            <div className="flex items-start mb-3">
              <svg
                className="w-5 h-5 text-green-500 mt-0.5 mr-2 flex-shrink-0"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M5 13l4 4L19 7"
                ></path>
              </svg>
              <span className="text-gray-600 text-sm">
                Tặng bảo hiểm xe 1 năm đầu tiên
              </span>
            </div>
            <div className="flex items-start">
              <svg
                className="w-5 h-5 text-green-500 mt-0.5 mr-2 flex-shrink-0"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M5 13l4 4L19 7"
                ></path>
              </svg>
              <span className="text-gray-600 text-sm">
                Hỗ trợ trả góp lãi suất 0% trong 6 tháng
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Thông tin chi tiết sản phẩm */}
      <div className="mt-16">
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 overflow-x-auto">
            <button
              className={`py-4 px-1 text-sm font-medium border-b-2 ${
                activeTab === "specs"
                  ? "border-red-600 text-red-600"
                  : "border-transparent text-gray-500 hover:text-gray-700"
              }`}
              onClick={() => setActiveTab("specs")}
            >
              Thông số kỹ thuật
            </button>
            <button
              className={`py-4 px-1 text-sm font-medium border-b-2 ${
                activeTab === "features"
                  ? "border-red-600 text-red-600"
                  : "border-transparent text-gray-500 hover:text-gray-700"
              }`}
              onClick={() => setActiveTab("features")}
            >
              Tính năng nổi bật
            </button>
            <button
              className={`py-4 px-1 text-sm font-medium border-b-2 ${
                activeTab === "reviews"
                  ? "border-red-600 text-red-600"
                  : "border-transparent text-gray-500 hover:text-gray-700"
              }`}
              onClick={() => setActiveTab("reviews")}
            >
              Đánh giá
            </button>
            <button
              className={`py-4 px-1 text-sm font-medium border-b-2 ${
                activeTab === "support"
                  ? "border-red-600 text-red-600"
                  : "border-transparent text-gray-500 hover:text-gray-700"
              }`}
              onClick={() => setActiveTab("support")}
            >
              Bảo hành & hỗ trợ
            </button>
          </nav>
        </div>

        <div className="py-6">
          {activeTab === "specs" && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div>
                <h3 className="text-lg font-medium text-gray-900 mb-4">
                  Thông số kỹ thuật
                </h3>
                <table className="min-w-full divide-y divide-gray-200">
                  <tbody className="bg-white divide-y divide-gray-200">
                    <tr>
                      <td className="py-3 text-sm text-gray-500 w-1/2">
                        Hãng sản xuất
                      </td>
                      <td className="py-3 text-sm font-medium text-gray-900">
                        {product.brandName}
                      </td>
                    </tr>
                    <tr>
                      <td className="py-3 text-sm text-gray-500">Loại xe</td>
                      <td className="py-3 text-sm font-medium text-gray-900">
                        {product.category}
                      </td>
                    </tr>
                    <tr>
                      <td className="py-3 text-sm text-gray-500">
                        Loại động cơ
                      </td>
                      <td className="py-3 text-sm font-medium text-gray-900">
                        {product.category === "xe điện"
                          ? "Động cơ điện"
                          : "4 thì, xy-lanh đơn, làm mát bằng không khí"}
                      </td>
                    </tr>
                    <tr>
                      <td className="py-3 text-sm text-gray-500">
                        {product.category === "xe điện"
                          ? "Công suất động cơ"
                          : "Dung tích xy-lanh"}
                      </td>
                      <td className="py-3 text-sm font-medium text-gray-900">
                        {product.category === "xe điện"
                          ? "1200W"
                          : product.category === "xe phân khối lớn"
                          ? "250cc - 1000cc"
                          : product.category === "xe côn tay"
                          ? "150cc - 175cc"
                          : "110cc - 125cc"}
                      </td>
                    </tr>
                    <tr>
                      <td className="py-3 text-sm text-gray-500">
                        Công suất tối đa
                      </td>
                      <td className="py-3 text-sm font-medium text-gray-900">
                        {product.category === "xe phân khối lớn"
                          ? "35 mã lực @ 8,000 rpm"
                          : product.category === "xe côn tay"
                          ? "15 mã lực @ 9,000 rpm"
                          : product.category === "xe số"
                          ? "8.5 mã lực @ 8,000 rpm"
                          : "12 mã lực @ 8,500 rpm"}
                      </td>
                    </tr>
                    <tr>
                      <td className="py-3 text-sm text-gray-500">
                        Dung tích bình xăng
                      </td>
                      <td className="py-3 text-sm font-medium text-gray-900">
                        {product.category === "xe phân khối lớn"
                          ? "14 lít"
                          : product.category === "xe điện"
                          ? "Không có"
                          : "4.5 lít"}
                      </td>
                    </tr>
                    <tr>
                      <td className="py-3 text-sm text-gray-500">
                        Hệ thống phanh trước/sau
                      </td>
                      <td className="py-3 text-sm font-medium text-gray-900">
                        {product.category === "xe phân khối lớn" ||
                        product.category === "xe côn tay"
                          ? "Đĩa/Đĩa"
                          : "Đĩa/Tang trống"}
                      </td>
                    </tr>
                    <tr>
                      <td className="py-3 text-sm text-gray-500">
                        Kích thước lốp trước/sau
                      </td>
                      <td className="py-3 text-sm font-medium text-gray-900">
                        {product.category === "xe phân khối lớn"
                          ? "110/70-17 / 150/60-17"
                          : product.category === "xe côn tay"
                          ? "90/90-17 / 120/70-17"
                          : "80/90-16 / 90/90-14"}
                      </td>
                    </tr>
                    <tr>
                      <td className="py-3 text-sm text-gray-500">
                        Khối lượng bản thân
                      </td>
                      <td className="py-3 text-sm font-medium text-gray-900">
                        {product.category === "xe phân khối lớn"
                          ? "185 kg"
                          : product.category === "xe côn tay"
                          ? "135 kg"
                          : product.category === "xe số"
                          ? "99 kg"
                          : "114 kg"}
                      </td>
                    </tr>
                    <tr>
                      <td className="py-3 text-sm text-gray-500">
                        Chiều cao yên
                      </td>
                      <td className="py-3 text-sm font-medium text-gray-900">
                        {product.category === "xe phân khối lớn"
                          ? "830 mm"
                          : product.category === "xe côn tay"
                          ? "795 mm"
                          : "760 mm"}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              <div>
                <h3 className="text-lg font-medium text-gray-900 mb-4">
                  Mô tả sản phẩm
                </h3>
                <div className="prose text-gray-600">
                  <p>
                    {product.description ||
                      `${product.name} - ${product.category} mới nhất từ ${product.brandName}. Thiết kế hiện đại, mạnh mẽ kết hợp với công nghệ tiên tiến, đem đến trải nghiệm lái xe tuyệt vời cho người dùng.`}
                  </p>

                  <div className="mt-6">
                    <h4 className="text-base font-medium text-gray-800">
                      Điểm nổi bật:
                    </h4>
                    <ul className="mt-2 space-y-2">
                      <li className="flex items-start">
                        <span className="text-red-600 mr-2">•</span>
                        <span>
                          Thiết kế thể thao, hiện đại phù hợp với giới trẻ
                        </span>
                      </li>
                      <li className="flex items-start">
                        <span className="text-red-600 mr-2">•</span>
                        <span>Động cơ mạnh mẽ, tiết kiệm nhiên liệu</span>
                      </li>
                      <li className="flex items-start">
                        <span className="text-red-600 mr-2">•</span>
                        <span>
                          Hệ thống phanh an toàn{" "}
                          {product.category === "xe phân khối lớn"
                            ? "ABS"
                            : "CBS"}
                        </span>
                      </li>
                      <li className="flex items-start">
                        <span className="text-red-600 mr-2">•</span>
                        <span>Khung xe vững chắc, cân bằng tốt</span>
                      </li>
                    </ul>
                  </div>

                  <p className="mt-4 text-sm text-gray-500">
                    Sản phẩm 100% chính hãng {product.brandName}. Xe được bảo
                    hành chính hãng 3 năm hoặc 30,000 km (tùy điều kiện nào đến
                    trước). Liên hệ showroom để nhận thêm ưu đãi mới nhất.
                  </p>
                </div>
              </div>
            </div>
          )}

          {activeTab === "features" && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div>
                <img
                  src={`http://localhost:8080/api/files/${product.avatar}`}
                  alt="Tính năng nổi bật"
                  className="rounded-lg w-full object-cover h-64"
                />
              </div>
              <div>
                <h3 className="text-lg font-medium text-gray-900 mb-4">
                  Tính năng nổi bật
                </h3>
                <div className="space-y-4">
                  <div className="flex items-start">
                    <div className="flex-shrink-0 w-10 h-10 bg-red-100 rounded-full flex items-center justify-center">
                      <svg
                        className="w-6 h-6 text-red-600"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth="2"
                          d="M13 10V3L4 14h7v7l9-11h-7z"
                        ></path>
                      </svg>
                    </div>
                    <div className="ml-4">
                      <h4 className="text-base font-medium text-gray-900">
                        Động cơ mạnh mẽ, tiết kiệm
                      </h4>
                      <p className="mt-1 text-sm text-gray-500">
                        {product.category === "xe điện"
                          ? "Động cơ điện tiết kiệm năng lượng, vận hành êm ái"
                          : "Động cơ 4 thì tiên tiến, phun xăng điện tử, tiết kiệm nhiên liệu tối ưu"}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-start">
                    <div className="flex-shrink-0 w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center">
                      <svg
                        className="w-6 h-6 text-blue-600"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth="2"
                          d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                        ></path>
                      </svg>
                    </div>
                    <div className="ml-4">
                      <h4 className="text-base font-medium text-gray-900">
                        Hệ thống an toàn tiên tiến
                      </h4>
                      <p className="mt-1 text-sm text-gray-500">
                        {product.category === "xe phân khối lớn"
                          ? "Trang bị hệ thống phanh ABS 2 kênh, kiểm soát lực kéo"
                          : "Hệ thống phanh CBS kết hợp, đảm bảo an toàn khi phanh gấp"}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-start">
                    <div className="flex-shrink-0 w-10 h-10 bg-green-100 rounded-full flex items-center justify-center">
                      <svg
                        className="w-6 h-6 text-green-600"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth="2"
                          d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
                        ></path>
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth="2"
                          d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                        ></path>
                      </svg>
                    </div>
                    <div className="ml-4">
                      <h4 className="text-base font-medium text-gray-900">
                        Công nghệ tiên tiến
                      </h4>
                      <p className="mt-1 text-sm text-gray-500">
                        {product.category === "xe ga" ||
                        product.category === "xe phân khối lớn"
                          ? "Hệ thống khóa thông minh Smart Key, màn hình LCD hiển thị đa thông tin"
                          : "Đèn LED tiết kiệm điện, hiển thị ECO thông minh"}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-start">
                    <div className="flex-shrink-0 w-10 h-10 bg-purple-100 rounded-full flex items-center justify-center">
                      <svg
                        className="w-6 h-6 text-purple-600"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth="2"
                          d="M19 14l-7 7m0 0l-7-7m7 7V3"
                        ></path>
                      </svg>
                    </div>
                    <div className="ml-4">
                      <h4 className="text-base font-medium text-gray-900">
                        Thiết kế tiện lợi
                      </h4>
                      <p className="mt-1 text-sm text-gray-500">
                        {product.category === "xe ga"
                          ? "Cốp xe rộng rãi, chứa được 2 mũ bảo hiểm cùng nhiều vật dụng cá nhân"
                          : "Thiết kế gọn gàng, cân đối, dễ di chuyển trong đô thị đông đúc"}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === "reviews" && (
            <div className="space-y-6">
              {/* Thống kê rating tổng quan */}
              <div className="bg-gray-50 p-6 rounded-lg">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="text-center">
                    <div className="text-4xl font-bold text-gray-900 mb-2">
                      {ratingStats.averageRating
                        ? ratingStats.averageRating.toFixed(1)
                        : "0.0"}
                    </div>
                    {renderStars(
                      Math.round(ratingStats.averageRating || 0),
                      "h-6 w-6"
                    )}
                    <p className="text-sm text-gray-600 mt-2">
                      Dựa trên {ratingStats.totalReviews} đánh giá
                    </p>
                  </div>

                  <div className="space-y-2">
                    {[5, 4, 3, 2, 1].map((star) => (
                      <div key={star} className="flex items-center space-x-2">
                        <span className="text-sm text-gray-600 w-8">
                          {star} sao
                        </span>
                        <div className="flex-1 bg-gray-200 rounded-full h-2">
                          <div
                            className="bg-yellow-400 h-2 rounded-full"
                            style={{
                              width:
                                ratingStats.totalReviews > 0
                                  ? `${
                                      ((ratingStats.ratingDistribution[star] ||
                                        0) /
                                        ratingStats.totalReviews) *
                                      100
                                    }%`
                                  : "0%",
                            }}
                          ></div>
                        </div>
                        <span className="text-sm text-gray-600 w-8">
                          {ratingStats.ratingDistribution[star] || 0}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Form đánh giá - chỉ hiện khi user có thể đánh giá */}
              {canUserReview.canReview && (
                <div className="bg-gray-50 p-6 rounded-lg">
                  <h3 className="text-lg font-medium text-gray-900 mb-4">
                    Viết đánh giá
                  </h3>
                  <div className="flex items-center mb-4">
                    <span className="text-sm text-gray-700 mr-2">
                      Đánh giá của bạn:
                    </span>
                    {renderStars(newReview.rating, "h-5 w-5", true, (rating) =>
                      setNewReview((prev) => ({ ...prev, rating }))
                    )}
                  </div>
                  <textarea
                    className="w-full border border-gray-300 rounded-md p-3 text-sm focus:ring-red-500 focus:border-red-500"
                    rows="4"
                    placeholder="Chia sẻ trải nghiệm của bạn về sản phẩm này..."
                    value={newReview.content}
                    onChange={(e) =>
                      setNewReview((prev) => ({
                        ...prev,
                        content: e.target.value,
                      }))
                    }
                  ></textarea>
                  <button
                    className="mt-4 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 text-sm font-medium disabled:bg-gray-400 disabled:cursor-not-allowed"
                    onClick={submitReview}
                    disabled={submittingReview}
                  >
                    {submittingReview ? "Đang gửi..." : "Gửi đánh giá"}
                  </button>
                </div>
              )}

              {/* Thông báo nếu chưa mua hoặc đã đánh giá */}
              {!canUserReview.canReview && (
                <div className="bg-yellow-50 border border-yellow-200 p-4 rounded-lg">
                  <p className="text-sm text-yellow-800">
                    {!canUserReview.hasPurchased
                      ? "Bạn cần mua sản phẩm này để có thể đánh giá."
                      : canUserReview.hasReviewed
                      ? "Bạn đã đánh giá sản phẩm này rồi."
                      : "Vui lòng đăng nhập để đánh giá sản phẩm."}
                  </p>
                </div>
              )}

              {/* Danh sách đánh giá */}
              <div className="space-y-4">
                <h3 className="text-lg font-medium text-gray-900">
                  Đánh giá từ khách hàng ({ratingStats.totalReviews})
                </h3>

                {comments.length === 0 ? (
                  <div className="text-center py-8">
                    <p className="text-gray-500">
                      Chưa có đánh giá nào cho sản phẩm này.
                    </p>
                    <p className="text-sm text-gray-400 mt-2">
                      Hãy là người đầu tiên đánh giá!
                    </p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {comments.map((comment) => (
                      <div
                        key={comment.id}
                        className="border-t border-gray-200 pt-4"
                      >
                        <div className="flex justify-between">
                          <span className="font-medium text-gray-900">
                            {comment.name || comment.username}
                          </span>
                          <span className="text-sm text-gray-500">
                            {new Date(comment.created).toLocaleDateString(
                              "vi-VN"
                            )}
                          </span>
                        </div>
                        <div className="flex mt-1">
                          {renderStars(comment.rating)}
                        </div>
                        <p className="mt-2 text-gray-600">{comment.content}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === "support" && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-gray-50 p-6 rounded-lg">
                <div className="flex items-center justify-center w-12 h-12 mx-auto bg-red-100 rounded-full mb-4"></div>
                <h3 className="text-lg font-medium text-center text-gray-900 mb-2">
                  Chế độ bảo hành
                </h3>
                <p className="text-gray-600 text-sm text-center">
                  Bảo hành chính hãng 3 năm hoặc 30,000 km (tùy điều kiện nào
                  đến trước). Được bảo hành tại tất cả các đại lý{" "}
                  {product.brandName} trên toàn quốc.
                </p>
              </div>

              <div className="bg-gray-50 p-6 rounded-lg">
                <div className="flex items-center justify-center w-12 h-12 mx-auto bg-blue-100 rounded-full mb-4">
                  <Calendar size={24} className="text-blue-600" />
                </div>
                <h3 className="text-lg font-medium text-center text-gray-900 mb-2">
                  Bảo dưỡng định kỳ
                </h3>
                <p className="text-gray-600 text-sm text-center">
                  Lần đầu: 1,000 km
                  <br />
                  Các lần tiếp theo: mỗi 3,000 km
                  <br />
                  Đặt lịch bảo dưỡng trực tuyến để được ưu tiên phục vụ.
                </p>
              </div>

              <div className="bg-gray-50 p-6 rounded-lg">
                <div className="flex items-center justify-center w-12 h-12 mx-auto bg-green-100 rounded-full mb-4">
                  <svg
                    className="w-6 h-6 text-green-600"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth="2"
                      d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z"
                    ></path>
                  </svg>
                </div>
                <h3 className="text-lg font-medium text-center text-gray-900 mb-2">
                  Hỗ trợ khách hàng
                </h3>
                <p className="text-gray-600 text-sm text-center">
                  Hotline: 1800-9999
                  <br />
                  Email: support@tmotoshop.com
                  <br />
                  Giờ làm việc: 8:00 - 20:00 (Tất cả các ngày)
                </p>
              </div>

              <div className="md:col-span-3 bg-gray-50 p-6 rounded-lg">
                <h3 className="text-lg font-medium text-gray-900 mb-4">
                  Câu hỏi thường gặp
                </h3>
                <div className="space-y-4">
                  <div>
                    <h4 className="font-medium text-gray-900">
                      Làm thế nào để đặt lịch bảo dưỡng?
                    </h4>
                    <p className="mt-1 text-sm text-gray-600">
                      Bạn có thể đặt lịch bảo dưỡng trực tuyến qua website chính
                      thức hoặc gọi hotline 1800-9999. Chúng tôi khuyến nghị đặt
                      lịch trước 2-3 ngày để đảm bảo được phục vụ đúng thời
                      gian.
                    </p>
                  </div>
                  <div>
                    <h4 className="font-medium text-gray-900">
                      Tôi có thể mua trả góp không?
                    </h4>
                    <p className="mt-1 text-sm text-gray-600">
                      Có, chúng tôi cung cấp nhiều gói trả góp với lãi suất ưu
                      đãi, thời gian từ 6-24 tháng. Bạn chỉ cần chuẩn bị CMND,
                      sổ hộ khẩu và chứng minh thu nhập (nếu cần).
                    </p>
                  </div>
                  <div>
                    <h4 className="font-medium text-gray-900">
                      Thời gian giao xe sau khi đặt cọc?
                    </h4>
                    <p className="mt-1 text-sm text-gray-600">
                      Thông thường xe có sẵn sẽ được giao trong vòng 1-3 ngày
                      làm việc. Với những phiên bản đặc biệt hoặc màu sắc hiếm
                      có thể mất 7-15 ngày tùy tình trạng kho.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
