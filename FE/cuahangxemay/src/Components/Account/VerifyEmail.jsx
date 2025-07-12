import React, { useState, useEffect } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import axios from "axios";
import { Mail, CheckCircle, XCircle, Loader, Clock } from "lucide-react";

export default function VerifyEmail() {
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // Lấy email từ state (nếu có) hoặc localStorage
  const email =
    location.state?.email ||
    localStorage.getItem("pendingVerificationEmail") ||
    "";

  // Lấy token từ URL parameters
  const token = searchParams.get("token");

  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [verificationStatus, setVerificationStatus] = useState("pending"); // pending, success, error

  // Tự động xác thực khi có token
  useEffect(() => {
    if (token) {
      handleAutoVerify();
    }
  }, [token]);

  const handleAutoVerify = async () => {
    setIsLoading(true);
    setError("");
    setSuccess("");

    try {
      const response = await axios.get(
        `http://localhost:8080/api/auth/verify-email?token=${token}`
      );

      if (response.data.success) {
        setSuccess(
          response.data.message || "Email đã được xác thực thành công!"
        );
        setVerificationStatus("success");

        // Xóa email pending từ localStorage
        localStorage.removeItem("pendingVerificationEmail");

        // Chuyển hướng đến trang đăng nhập sau 3 giây
        setTimeout(() => {
          navigate("/login", {
            state: {
              message:
                "Email đã được xác thực. Bạn có thể đăng nhập ngay bây giờ.",
            },
          });
        }, 3000);
      } else {
        setError(response.data.message || "Link xác thực không hợp lệ.");
        setVerificationStatus("error");
      }
    } catch (err) {
      let errorMessage = "Đã xảy ra lỗi khi xác thực email.";

      if (err.response?.data?.message) {
        errorMessage = err.response.data.message;
      } else if (err.response?.status === 400) {
        errorMessage = "Link xác thực không hợp lệ hoặc đã hết hạn.";
      } else if (err.response?.status === 404) {
        errorMessage = "Token xác thực không tồn tại.";
      }

      setError(errorMessage);
      setVerificationStatus("error");
      console.error("Lỗi xác thực email:", err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleResendVerification = async () => {
    if (!email) {
      setError("Không có thông tin email. Vui lòng thử đăng ký lại.");
      return;
    }

    setIsLoading(true);
    setError("");
    setSuccess("");

    try {
      const response = await axios.post(
        `http://localhost:8080/api/auth/resend-verification?email=${encodeURIComponent(
          email
        )}`
      );

      if (response.data.success) {
        setSuccess(
          "Link xác thực mới đã được gửi đến email của bạn. Vui lòng kiểm tra hộp thư."
        );
      } else {
        setError(response.data.message || "Không thể gửi lại link xác thực.");
      }
    } catch (err) {
      let errorMessage = "Đã xảy ra lỗi khi gửi lại link xác thực.";

      if (err.response?.data?.message) {
        errorMessage = err.response.data.message;
      }

      setError(errorMessage);
      console.error("Lỗi gửi lại link xác thực:", err);
    } finally {
      setIsLoading(false);
    }
  };

  // Render loading state
  if (isLoading && token) {
    return (
      <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 px-6 lg:px-8">
        <div className="sm:mx-auto sm:w-full sm:max-w-md text-center">
          <Loader className="h-12 w-12 text-blue-500 animate-spin mx-auto" />
          <h2 className="mt-6 text-2xl font-bold text-gray-900">
            Đang xác thực email...
          </h2>
          <p className="mt-2 text-sm text-gray-600">
            Vui lòng đợi trong giây lát
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="flex justify-center">
          {verificationStatus === "success" && (
            <CheckCircle className="h-12 w-12 text-green-500" />
          )}
          {verificationStatus === "error" && (
            <XCircle className="h-12 w-12 text-red-500" />
          )}
          {verificationStatus === "pending" && (
            <Mail className="h-12 w-12 text-blue-500" />
          )}
        </div>

        <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
          {verificationStatus === "success" && "Xác thực thành công!"}
          {verificationStatus === "error" && "Xác thực thất bại"}
          {verificationStatus === "pending" && "Xác thực email"}
        </h2>

        <p className="mt-2 text-center text-sm text-gray-600">
          {verificationStatus === "success" &&
            "Email của bạn đã được xác thực thành công"}
          {verificationStatus === "error" &&
            "Có vấn đề với link xác thực của bạn"}
          {verificationStatus === "pending" &&
            "Vui lòng kiểm tra email và nhấp vào link xác thực"}
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-8 px-6 shadow rounded-lg sm:px-10 border border-gray-200">
          {/* Hiển thị thông báo lỗi */}
          {error && (
            <div className="mb-4 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded flex items-start">
              <XCircle className="h-5 w-5 mr-2 mt-0.5 flex-shrink-0" />
              <div>
                <p className="font-medium">Lỗi xác thực</p>
                <p className="text-sm">{error}</p>
              </div>
            </div>
          )}

          {/* Hiển thị thông báo thành công */}
          {success && (
            <div className="mb-4 bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded flex items-start">
              <CheckCircle className="h-5 w-5 mr-2 mt-0.5 flex-shrink-0" />
              <div>
                <p className="font-medium">Thành công</p>
                <p className="text-sm">{success}</p>
              </div>
            </div>
          )}

          {/* Hiển thị thông tin email */}
          {email && (
            <div className="mb-6 bg-blue-50 border border-blue-200 text-blue-700 px-4 py-3 rounded flex items-center">
              <Mail className="h-5 w-5 mr-2 flex-shrink-0" />
              <div className="text-sm">
                <span>Email đăng ký: </span>
                <span className="font-medium">{email}</span>
              </div>
            </div>
          )}

          {/* Nội dung chính */}
          <div className="space-y-6">
            {/* Nếu chưa có token (user vào trang trực tiếp) */}
            {!token && verificationStatus === "pending" && (
              <div className="text-center space-y-4">
                <div className="bg-yellow-50 border border-yellow-200 text-yellow-800 px-4 py-3 rounded flex items-start">
                  <Clock className="h-5 w-5 mr-2 mt-0.5 flex-shrink-0" />
                  <div className="text-sm">
                    <p className="font-medium">Chờ xác thực email</p>
                    <p>
                      Chúng tôi đã gửi một link xác thực đến email của bạn. Vui
                      lòng kiểm tra hộp thư và nhấp vào link để hoàn tất đăng
                      ký.
                    </p>
                  </div>
                </div>

                <div className="text-sm text-gray-600 space-y-2">
                  <p>• Kiểm tra cả thư mục spam/junk</p>
                  <p>• Link xác thực có hiệu lực trong 1 giờ</p>
                  <p>
                    • Nếu không nhận được email, bạn có thể gửi lại bên dưới
                  </p>
                </div>
              </div>
            )}

            {/* Nếu xác thực thành công */}
            {verificationStatus === "success" && (
              <div className="text-center space-y-4">
                <div className="bg-green-50 border border-green-200 text-green-800 px-4 py-3 rounded">
                  <p className="font-medium">🎉 Chúc mừng!</p>
                  <p className="text-sm mt-1">
                    Tài khoản của bạn đã được kích hoạt thành công. Bạn sẽ được
                    chuyển đến trang đăng nhập sau vài giây...
                  </p>
                </div>

                <button
                  onClick={() => navigate("/login")}
                  className="w-full bg-green-600 text-white py-2 px-4 rounded-md hover:bg-green-700 transition-colors"
                >
                  Đăng nhập ngay
                </button>
              </div>
            )}

            {/* Nếu có lỗi */}
            {verificationStatus === "error" && (
              <div className="space-y-4">
                <div className="bg-gray-50 border border-gray-200 text-gray-700 px-4 py-3 rounded text-sm">
                  <p className="font-medium mb-2">Các nguyên nhân có thể:</p>
                  <ul className="list-disc list-inside space-y-1 text-sm">
                    <li>Link xác thực đã hết hạn (quá 1 giờ)</li>
                    <li>Link đã được sử dụng trước đó</li>
                    <li>Link không đúng định dạng</li>
                  </ul>
                </div>
              </div>
            )}

            {/* Nút gửi lại (hiện khi pending hoặc error) */}
            {(verificationStatus === "pending" ||
              verificationStatus === "error") && (
              <div className="space-y-3">
                <button
                  onClick={handleResendVerification}
                  disabled={isLoading || !email}
                  className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
                >
                  {isLoading ? "Đang gửi..." : "Gửi lại link xác thực"}
                </button>

                <div className="text-center text-sm text-gray-600">
                  <span>Không phải email của bạn? </span>
                  <button
                    onClick={() => navigate("/register")}
                    className="text-blue-600 hover:text-blue-500 font-medium"
                  >
                    Đăng ký lại
                  </button>
                </div>
              </div>
            )}

            {/* Liên kết hỗ trợ */}
            <div className="text-center pt-4 border-t border-gray-200">
              <div className="space-y-2 text-sm">
                <button
                  onClick={() => navigate("/login")}
                  className="text-gray-600 hover:text-gray-500 block w-full"
                >
                  ← Quay lại trang đăng nhập
                </button>
                <a
                  href="/contact"
                  className="text-blue-600 hover:text-blue-500 block"
                >
                  Cần hỗ trợ? Liên hệ chúng tôi
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
