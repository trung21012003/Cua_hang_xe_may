import { useState } from "react";
import { Mail } from "lucide-react";
import React from "react";
import axios from "axios";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async () => {
    // Validate email
    if (!email || !email.includes("@")) {
      setError("Vui lòng nhập địa chỉ email hợp lệ");
      return;
    }

    setIsLoading(true);
    setError("");

    try {
      const response = await axios.post("http://localhost:8080/api/auth/forgot-password", { email });

      if (response.data.success) {
        setIsSubmitted(true);
      } else {
        setError(response.data.message || "Đã xảy ra lỗi. Vui lòng thử lại.");
      }
    } catch (error) {
      setError(
        error.response?.data?.message || 
        "Đã xảy ra lỗi khi gửi yêu cầu. Vui lòng thử lại."
      );
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
          Quên mật khẩu
        </h2>
        <p className="mt-2 text-center text-sm text-gray-600">
          {isSubmitted
            ? "Vui lòng kiểm tra email của bạn."
            : "Nhập email để lấy lại mật khẩu"}
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-8 px-6 shadow rounded-lg sm:px-10 border border-gray-200">
          {!isSubmitted ? (
            <div className="mb-0 space-y-6">
              {error && (
                <div className="bg-red-50 p-4 rounded-md">
                  <div className="flex">
                    <div className="flex-shrink-0">
                      <svg
                        className="h-5 w-5 text-red-400"
                        xmlns="http://www.w3.org/2000/svg"
                        viewBox="0 0 20 20"
                        fill="currentColor"
                      >
                        <path
                          fillRule="evenodd"
                          d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                          clipRule="evenodd"
                        />
                      </svg>
                    </div>
                    <div className="ml-3">
                      <h3 className="text-sm font-medium text-red-800">Lỗi</h3>
                      <div className="mt-2 text-sm text-red-700">
                        <p>{error}</p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              <div>
                <label
                  htmlFor="email"
                  className="block text-sm font-medium text-gray-700"
                >
                  Email
                </label>
                <div className="mt-1 relative rounded-md shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Mail className="h-5 w-5 text-gray-400" />
                  </div>
                  <input
                    id="email"
                    name="email"
                    type="email"
                    autoComplete="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-red-500 focus:border-red-500"
                    placeholder="you@example.com"
                  />
                </div>
              </div>

              <div>
                <button
                  type="button"
                  onClick={handleSubmit}
                  disabled={isLoading}
                  className={`w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 ${
                    isLoading ? "opacity-70 cursor-not-allowed" : ""
                  }`}
                >
                  {isLoading ? "Đang xử lý..." : "Gửi yêu cầu"}
                </button>
              </div>

              <div className="flex items-center justify-center">
                <div className="text-sm">
                  <a
                    href="/login"
                    className="font-medium text-red-600 hover:text-red-500"
                  >
                    Quay lại trang đăng nhập
                  </a>
                </div>
              </div>
            </div>
          ) : (
            <div className="space-y-6">
              <div className="bg-green-50 p-4 rounded-md">
                <div className="flex">
                  <div className="flex-shrink-0">
                    <svg
                      className="h-5 w-5 text-green-400"
                      xmlns="http://www.w3.org/2000/svg"
                      viewBox="0 0 20 20"
                      fill="currentColor"
                      aria-hidden="true"
                    >
                      <path
                        fillRule="evenodd"
                        d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                        clipRule="evenodd"
                      />
                    </svg>
                  </div>
                  <div className="ml-3">
                    <h3 className="text-sm font-medium text-green-800">
                      Yêu cầu đã được gửi!
                    </h3>
                    <div className="mt-2 text-sm text-green-700">
                      <p>
                        Chúng tôi đã gửi một email với hướng dẫn lấy lại mật
                        khẩu đến {email}. Vui lòng kiểm tra hộp thư đến của bạn.
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-center">
                <div className="text-sm">
                  <a
                    href="#"
                    className="font-medium text-red-600 hover:text-red-500"
                  >
                    Quay lại trang đăng nhập
                  </a>
                </div>
              </div>

              <div className="flex items-center justify-center">
                <button
                  type="button"
                  onClick={() => setIsSubmitted(false)}
                  className="text-sm font-medium text-gray-600 hover:text-gray-500"
                >
                  Không nhận được email? Thử lại
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
