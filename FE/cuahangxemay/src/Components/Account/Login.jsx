import React, { useContext, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { Eye, EyeOff, Lock, Mail, User } from "lucide-react";
import FacebookIcon from "@mui/icons-material/Facebook";
import GoogleIcon from "@mui/icons-material/Google";
import { UserContext } from "../contexts/GetUser";

export default function LoginPage() {
  const { checkAuth } = useContext(UserContext);
  const [showPassword, setShowPassword] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [rememberMe, setRememberMe] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [isPendingVerification, setIsPendingVerification] = useState(false);
  const [resendLoading, setResendLoading] = useState(false);
  const [resendSuccess, setResendSuccess] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setIsPendingVerification(false);
    setResendSuccess(false);
    setLoading(true);

    try {
      // Gửi yêu cầu đăng nhập tới backend
      const response = await axios.post(
        "http://localhost:8080/api/auth/login",
        {
          username: username,
          password: password,
        }
      );

      console.log("Login response:", response.data); // Debug log


      if (
        response.data.success &&
        response.data.data &&
        response.data.data.token
      ) {
        const token = response.data.data.token;

        // Lưu token vào localStorage
        localStorage.setItem("jwtToken", token);

        console.log("Token saved to localStorage:", token); // Debug log

        // Cập nhật context
        await checkAuth();

        // Thông báo thành công
        console.log("Đăng nhập thành công!");

        // Điều hướng về trang chủ
        navigate("/");
      } else {
        throw new Error("Invalid response format");
      }
    } catch (err) {
      console.error("Lỗi đăng nhập:", err);
      const errorMessage = err.response?.data?.message || err.message || "Đăng nhập thất bại. Vui lòng thử lại.";
      setError(errorMessage);

      // Check if the error is about pending verification
      if (errorMessage.includes("chưa được kích hoạt") || errorMessage.includes("xác thực")) {
        setIsPendingVerification(true);
        // Try to get the email from the username if it looks like an email
        if (username.includes('@')) {
          setEmail(username);
        }
      }
    } finally {
      setLoading(false);
    }
  };

  const handleResendVerification = async () => {
    if (!email || !email.includes('@')) {
      setError("Vui lòng nhập địa chỉ email hợp lệ");
      return;
    }

    setResendLoading(true);
    setResendSuccess(false);
    setError("");

    try {
      const response = await axios.post(
        "http://localhost:8080/api/auth/resend-verification",
        { email }
      );

      if (response.data.success) {
        setResendSuccess(true);
      } else {
        setError(response.data.message || "Không thể gửi email xác thực. Vui lòng thử lại.");
      }
    } catch (err) {
      setError(
        err.response?.data?.message ||
        err.message ||
        "Đã xảy ra lỗi khi gửi yêu cầu. Vui lòng thử lại."
      );
    } finally {
      setResendLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
          Đăng nhập
        </h2>
        <p className="mt-2 text-center text-sm text-gray-600">
          Hoặc{" "}
          <a
            href="resigter"
            className="font-medium text-red-600 hover:text-red-500"
          >
            đăng ký tài khoản mới
          </a>
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-8 px-6 shadow rounded-lg sm:px-10 border border-gray-200">
          {/* Hiển thị thông báo lỗi nếu có */}
          {error && !isPendingVerification && (
            <div className="mb-4 text-center text-sm text-red-600 bg-red-100 p-2 rounded">
              {error}
            </div>
          )}

          {/* Hiển thị form gửi lại email xác thực nếu tài khoản chưa được kích hoạt */}
          {isPendingVerification && (
            <div className="mb-6 p-4 border border-yellow-300 rounded-md bg-yellow-50">
              <h3 className="text-sm font-medium text-yellow-800 mb-2">
                Tài khoản chưa được kích hoạt
              </h3>
              <p className="text-sm text-yellow-700 mb-4">
                Vui lòng kiểm tra email của bạn để xác thực tài khoản. Nếu bạn chưa nhận được email xác thực, bạn có thể yêu cầu gửi lại.
              </p>

              <div className="space-y-3">
                <div>
                  <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                    Email
                  </label>
                  <input
                    type="email"
                    id="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-red-500 focus:border-red-500 sm:text-sm"
                    placeholder="Nhập email đăng ký của bạn"
                  />
                </div>

                <div className="flex items-center justify-between">
                  <button
                    type="button"
                    onClick={handleResendVerification}
                    disabled={resendLoading}
                    className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50"
                  >
                    {resendLoading ? "Đang gửi..." : "Gửi lại email xác thực"}
                  </button>

                  <button
                    type="button"
                    onClick={() => setIsPendingVerification(false)}
                    className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
                  >
                    Quay lại đăng nhập
                  </button>
                </div>

                {resendSuccess && (
                  <div className="mt-3 p-2 bg-green-50 border border-green-200 rounded-md">
                    <p className="text-sm text-green-700">
                      Email xác thực đã được gửi lại. Vui lòng kiểm tra hộp thư đến của bạn.
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {!isPendingVerification && (
            <form className="mb-0 space-y-6" onSubmit={handleSubmit}>
              <div>
                <label
                  htmlFor="username"
                  className="block text-sm font-medium text-gray-700"
                >
                  Tài khoản
                </label>
                <div className="mt-1 relative rounded-md shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <User className="h-5 w-5 text-gray-400" />
                  </div>
                  <input
                    id="username"
                    name="username"
                    type="text"
                    autoComplete="username"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-red-500 focus:border-red-500"
                    placeholder="Nhập tài khoản của bạn"
                  />
                </div>
              </div>

              <div>
                <label
                  htmlFor="password"
                  className="block text-sm font-medium text-gray-700"
                >
                  Mật khẩu
                </label>
                <div className="mt-1 relative rounded-md shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Lock className="h-5 w-5 text-gray-400" />
                  </div>
                  <input
                    id="password"
                    name="password"
                    type={showPassword ? "text" : "password"}
                    autoComplete="current-password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="block w-full pl-10 pr-10 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-red-500 focus:border-red-500"
                    placeholder="••••••••"
                  />
                  <div className="absolute inset-y-0 right-0 pr-3 flex items-center">
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="text-gray-400 hover:text-gray-500 focus:outline-none"
                    >
                      {showPassword ? (
                        <EyeOff className="h-5 w-5" />
                      ) : (
                        <Eye className="h-5 w-5" />
                      )}
                    </button>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div className="flex items-center">
                  <input
                    id="remember-me"
                    name="remember-me"
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    className="h-4 w-4 text-red-600 focus:ring-red-500 border-gray-300 rounded"
                  />
                  <label
                    htmlFor="remember-me"
                    className="ml-2 block text-sm text-gray-700"
                  >
                    Ghi nhớ đăng nhập
                  </label>
                </div>

                <div className="text-sm">
                  <a
                    href="/forgot-password"
                    className="font-medium text-red-600 hover:text-red-500"
                  >
                    Quên mật khẩu?
                  </a>
                </div>
              </div>

              <div>
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50"
                >
                  {loading ? "Đang đăng nhập..." : "Đăng nhập"}
                </button>
              </div>
            </form>
          )}

          <div className="mt-6">
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-300"></div>
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-white text-gray-500">
                  Hoặc đăng nhập với
                </span>
              </div>
            </div>

            <div className="mt-6 grid grid-cols-2 gap-3">
              <div>
                <a
                  href="#"
                  className="w-full inline-flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-500 hover:bg-gray-50"
                >
                  <FacebookIcon className="w-5 h-5 text-blue-600" />
                  <span className="ml-2">Facebook</span>
                </a>
              </div>

              <div>
                <a
                  href="#"
                  className="w-full inline-flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-500 hover:bg-gray-50"
                >
                  <GoogleIcon className="w-5 h-5 text-red-600" />
                  <span className="ml-2">Google</span>
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
