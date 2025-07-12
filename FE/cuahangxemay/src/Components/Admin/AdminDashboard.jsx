import React, { useState, useEffect, useContext } from "react";
import { UserContext } from "../contexts/GetUser";
import axios from "axios";
import {
  Users,
  Package,
  ShoppingCart,
  TrendingUp,
  Settings,
  BarChart3,
  RefreshCw,
  Bell,
  DollarSign,
  Activity,
  AlertTriangle,
  CheckCircle,
} from "lucide-react";
import {
  UsersTab,
  OrdersTab,
  ProductsTab,
  AnalyticsTab,
  SettingsTab,
} from "./AdminTabComponents";

const AdminDashboard = () => {
  const { user, isLoggedIn } = useContext(UserContext);
  const [activeTab, setActiveTab] = useState("overview");
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  // Data states
  const [systemStats, setSystemStats] = useState(null);
  const [users, setUsers] = useState([]);
  const [orders, setOrders] = useState([]);
  const [products, setProducts] = useState([]);
  const [recentActivities, setRecentActivities] = useState([]);

  // Pagination states
  const [userPage, setUserPage] = useState(0);
  const [orderPage, setOrderPage] = useState(0);
  const [productPage, setProductPage] = useState(0);

  // Filter states
  const [userFilter, setUserFilter] = useState("");
  const [orderFilter, setOrderFilter] = useState("all");
  const [dateRange, setDateRange] = useState("last7days");

  // Check if user is admin
  const isAdmin = () => {
    return user && user.role === "0";
  };

  // API calls
  const fetchSystemStats = async () => {
    try {
      const token = localStorage.getItem("jwtToken");
      const response = await axios.get(
        "http://localhost:8080/api/admin/stats",
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      setSystemStats(response.data);
    } catch (error) {
      console.error("Error fetching system stats:", error);
    }
  };

  const fetchUsers = async (page = 0, search = "") => {
    try {
      const token = localStorage.getItem("jwtToken");
      const params = new URLSearchParams({
        page: page.toString(),
        size: "10",
        sortBy: "created",
        sortDir: "desc",
      });

      if (search) {
        params.append("search", search);
      }

      const response = await axios.get(
        `http://localhost:8080/api/admin/users?${params}`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      setUsers(
        Array.isArray(response.data)
          ? response.data
          : response.data.content || []
      );
    } catch (error) {
      console.error("Error fetching users:", error);
      setUsers([]);
      alert(
        "Lỗi khi tải danh sách người dùng: " +
          (error.response?.data?.message || error.message)
      );
    }
  };

  const fetchOrders = async (page = 0, status = "all") => {
    try {
      const token = localStorage.getItem("jwtToken");
      const params = new URLSearchParams({
        page: page.toString(),
        size: "10",
        sortBy: "orderDate",
        sortDir: "desc",
      });

      if (status !== "all") {
        params.append("status", status);
      }

      const response = await axios.get(
        `http://localhost:8080/api/orders/admin/all?${params}`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      const ordersData = Array.isArray(response.data)
        ? response.data
        : response.data.content || [];
      setOrders(ordersData);
    } catch (error) {
      console.error("Error fetching orders:", error);
      setOrders([]);
      alert(
        "Lỗi khi tải danh sách đơn hàng: " +
          (error.response?.data?.message || error.message)
      );
    }
  };

  const fetchProducts = async () => {
    try {
      const token = localStorage.getItem("jwtToken");
      if (!token) {
        throw new Error("No authentication token found");
      }

      const response = await axios.get(
        "http://localhost:8080/api/products/manage",
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (response.data && response.data.content) {
        setProducts(response.data.content);
      }
    } catch (error) {
      console.error("Error fetching products:", error);
      setProducts([]);
    }
  };

  const addProduct = async (productData) => {
    try {
      const token = localStorage.getItem("jwtToken");
      if (!token) {
        throw new Error("No authentication token found");
      }

      // Create FormData object to handle file uploads
      const formData = new FormData();
      
      // Add product avatar
      if (productData.avatar) {
        formData.append("avatar", productData.avatar);
      }

      // Add basic product information
      formData.append("name", productData.name);
      formData.append("description", productData.description);
      formData.append("price", productData.price);
      formData.append("weight", productData.weight);
      formData.append("size", productData.size);
      formData.append("petrolCapacity", productData.petrolCapacity);
      formData.append("saddleHeight", productData.saddleHeight);
      formData.append("wheelSize", productData.wheelSize);
      formData.append("beforeFork", productData.beforeFork);
      formData.append("afterFork", productData.afterFork);
      formData.append("maxiumCapacity", productData.maxiumCapacity);
      formData.append("oilCapacity", productData.oilCapacity);
      formData.append("fuelConsumption", productData.fuelConsumption);
      formData.append("cylinderCapacity", productData.cylinderCapacity);
      formData.append("maxiumMoment", productData.maxiumMoment);
      formData.append("compressionRatio", productData.compressionRatio);
      formData.append("engieType", productData.engieType);
      formData.append("status", productData.status);

      // Add versions and colors
      if (productData.versionColors && productData.versionColors.length > 0) {
        productData.versionColors.forEach((version, versionIndex) => {
          formData.append(`versionColors[${versionIndex}].versionName`, version.versionName);
          formData.append(`versionColors[${versionIndex}].price`, version.price);
          
          if (version.colors && version.colors.length > 0) {
            version.colors.forEach((color, colorIndex) => {
              formData.append(`versionColors[${versionIndex}].colors[${colorIndex}].color`, color.color);
              formData.append(`versionColors[${versionIndex}].colors[${colorIndex}].price`, color.price);
              formData.append(`versionColors[${versionIndex}].colors[${colorIndex}].value`, color.value);
              formData.append(`versionColors[${versionIndex}].colors[${colorIndex}].quantity`, color.quantity);
              
              if (color.photo) {
                formData.append(`versionColors[${versionIndex}].colors[${colorIndex}].photo`, color.photo);
              }
            });
          }
        });
      }

      const response = await axios.post(
        "http://localhost:8080/api/products/manage",
        formData,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "multipart/form-data",
          },
        }
      );

      if (response.data) {
        // Update local state immediately
        setProducts((prevProducts) => [...prevProducts, response.data]);
        // Fetch fresh data
        await fetchProducts();
        return response.data;
      }
    } catch (error) {
      console.error("Error adding product:", error);
      if (error.response) {
        console.error("Error response:", error.response.data);
      }
      throw error;
    }
  };

  const updateProduct = async (productId, productData) => {
    try {
      const token = localStorage.getItem("jwtToken");
      if (!token) {
        throw new Error("No authentication token found");
      }

      const response = await axios.put(
        `http://localhost:8080/api/products/manage/${productId}`,
        productData,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (response.data) {
        // Update local state immediately
        setProducts((prevProducts) =>
          prevProducts.map((p) => (p.id === productId ? response.data : p))
        );
        // Fetch fresh data
        await fetchProducts();
        return response.data;
      }
    } catch (error) {
      console.error("Error updating product:", error);
      throw error;
    }
  };

  const deleteProduct = async (productId) => {
    try {
      const token = localStorage.getItem("jwtToken");
      if (!token) {
        throw new Error("No authentication token found");
      }

      await axios.delete(
        `http://localhost:8080/api/products/manage/${productId}`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      // Update local state immediately
      setProducts((prevProducts) =>
        prevProducts.filter((p) => p.id !== productId)
      );
      // Fetch fresh data
      await fetchProducts();
      return true;
    } catch (error) {
      console.error("Error deleting product:", error);
      throw error;
    }
  };

  // User management actions
  const updateUserRole = async (userId, newRole) => {
    try {
      const token = localStorage.getItem("jwtToken");
      await axios.put(
        `http://localhost:8080/api/admin/users/${userId}/role?roleCode=${newRole}`,
        {},
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      alert("Cập nhật vai trò người dùng thành công!");
      fetchUsers(userPage, userFilter);
      fetchSystemStats(); // Refresh stats
    } catch (error) {
      console.error("Error updating user role:", error);
      alert(
        "Lỗi khi cập nhật vai trò người dùng: " +
          (error.response?.data?.message || error.message)
      );
    }
  };

  const updateUserStatus = async (userId, newStatus) => {
    try {
      const token = localStorage.getItem("jwtToken");
      await axios.put(
        `http://localhost:8080/api/admin/users/${userId}/status?status=${newStatus}`,
        {},
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      alert("Cập nhật trạng thái người dùng thành công!");
      fetchUsers(userPage, userFilter);
      fetchSystemStats();
    } catch (error) {
      console.error("Error updating user status:", error);
      alert(
        "Lỗi khi cập nhật trạng thái người dùng: " +
          (error.response?.data?.message || error.message)
      );
    }
  };

  const deleteUser = async (userId) => {
    if (
      !confirm(
        "Bạn có chắc chắn muốn xóa người dùng này? Hành động này không thể hoàn tác."
      )
    ) {
      return;
    }

    try {
      const token = localStorage.getItem("jwtToken");
      await axios.delete(`http://localhost:8080/api/admin/users/${userId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      alert("Xóa người dùng thành công!");
      fetchUsers(userPage, userFilter);
      fetchSystemStats();
    } catch (error) {
      console.error("Error deleting user:", error);
      alert(
        "Lỗi khi xóa người dùng: " +
          (error.response?.data?.message || error.message)
      );
    }
  };

  // Order management actions
  const updateOrderStatus = async (orderId, newStatus) => {
    try {
      const token = localStorage.getItem("jwtToken");
      await axios.put(
        `http://localhost:8080/api/orders/admin/${orderId}/status?status=${newStatus}`,
        {},
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      
      // Update local state immediately for better UX
      setOrders(prevOrders => 
        prevOrders.map(order => 
          order.id === orderId 
            ? { ...order, status: newStatus }
            : order
        )
      );
      
      // Then fetch fresh data from server
      await fetchOrders(orderPage, orderFilter);
      
      alert("Cập nhật trạng thái đơn hàng thành công!");
    } catch (error) {
      console.error("Error updating order status:", error);
      alert(
        "Lỗi khi cập nhật trạng thái đơn hàng: " +
          (error.response?.data?.message || error.message)
      );
    }
  };

  // Utility functions
  const getRoleDisplayName = (roleCode) => {
    switch (roleCode) {
      case "0":
        return "Admin";
      case "1":
        return "User";
      case "2":
        return "Manager";
      case "3":
        return "Guest";
      default:
        return "Unknown";
    }
  };

  const formatCurrency = (amount) => {
    return new Intl.NumberFormat("vi-VN", {
      style: "currency",
      currency: "VND",
    }).format(amount);
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString("vi-VN", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  // Refresh all data
  const refreshAllData = async () => {
    setRefreshing(true);
    try {
      await Promise.all([
        fetchSystemStats(),
        fetchUsers(userPage, userFilter),
        fetchOrders(orderPage, orderFilter),
        fetchProducts(),
      ]);
    } finally {
      setRefreshing(false);
    }
  };

  // Initial data load
  useEffect(() => {
    if (isAdmin()) {
      refreshAllData();
    }
  }, [user]);

  // Tab change effect
  useEffect(() => {
    if (!isAdmin()) return;

    switch (activeTab) {
      case "users":
        fetchUsers(userPage, userFilter);
        break;
      case "orders":
        fetchOrders(orderPage, orderFilter);
        break;
      case "products":
        fetchProducts();
        break;
    }
  }, [activeTab, userPage, orderPage, productPage, userFilter, orderFilter]);

  if (!isLoggedIn || !isAdmin()) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="bg-white p-8 rounded-lg shadow-md text-center">
          <AlertTriangle className="mx-auto h-12 w-12 text-red-500 mb-4" />
          <h2 className="text-2xl font-bold text-gray-900 mb-2">
            Truy cập bị từ chối
          </h2>
          <p className="text-gray-600">
            Bạn cần quyền quản trị viên để truy cập trang này.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">
                Trang Quản Lí
              </h1>
              <p className="text-sm text-gray-500">
                Chào mừng trở lại, {user?.name || user?.username}
              </p>
            </div>
            <div className="flex items-center space-x-4">
              <button
                onClick={refreshAllData}
                disabled={refreshing}
                className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                <RefreshCw
                  className={`h-4 w-4 mr-2 ${refreshing ? "animate-spin" : ""}`}
                />
                Làm mới
              </button>
              <div className="flex items-center space-x-2">
                <Bell className="h-5 w-5 text-gray-400" />
                <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center text-white text-sm font-medium">
                  {user?.username?.[0]?.toUpperCase()}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="bg-white border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <nav className="flex space-x-8">
            {[
              { id: "overview", label: "Tổng quan", icon: BarChart3 },
              { id: "users", label: "Người dùng", icon: Users },
              { id: "orders", label: "Đơn hàng", icon: ShoppingCart },
              { id: "products", label: "Sản phẩm", icon: Package },
              { id: "analytics", label: "Phân tích", icon: TrendingUp },
              { id: "settings", label: "Cài đặt", icon: Settings },
            ].map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center px-1 py-4 text-sm font-medium border-b-2 ${
                    activeTab === tab.id
                      ? "border-blue-500 text-blue-600"
                      : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
                  }`}
                >
                  <Icon className="h-4 w-4 mr-2" />
                  {tab.label}
                </button>
              );
            })}
          </nav>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === "overview" && (
          <OverviewTab
            systemStats={systemStats}
            users={users.slice(0, 5)}
            orders={orders.slice(0, 5)}
            formatCurrency={formatCurrency}
            formatDate={formatDate}
            getRoleDisplayName={getRoleDisplayName}
          />
        )}

        {activeTab === "users" && (
          <UsersTab
            users={users}
            userFilter={userFilter}
            setUserFilter={setUserFilter}
            userPage={userPage}
            setUserPage={setUserPage}
            updateUserRole={updateUserRole}
            updateUserStatus={updateUserStatus}
            deleteUser={deleteUser}
            getRoleDisplayName={getRoleDisplayName}
            formatDate={formatDate}
            fetchUsers={fetchUsers}
          />
        )}

        {activeTab === "orders" && (
          <OrdersTab
            orders={orders}
            orderFilter={orderFilter}
            setOrderFilter={setOrderFilter}
            orderPage={orderPage}
            setOrderPage={setOrderPage}
            updateOrderStatus={updateOrderStatus}
            formatCurrency={formatCurrency}
            formatDate={formatDate}
          />
        )}

        {activeTab === "products" && (
          <ProductsTab
            products={products}
            formatCurrency={formatCurrency}
            formatDate={formatDate}
            fetchProducts={fetchProducts}
            addProduct={addProduct}
            updateProduct={updateProduct}
            deleteProduct={deleteProduct}
          />
        )}

        {activeTab === "analytics" && (
          <AnalyticsTab
            systemStats={systemStats}
            orders={orders}
            users={users}
            formatCurrency={formatCurrency}
          />
        )}

        {activeTab === "settings" && <SettingsTab />}
      </div>
    </div>
  );
};

// Overview Tab Component
const OverviewTab = ({
  systemStats,
  users,
  orders,
  formatCurrency,
  formatDate,
  getRoleDisplayName,
}) => {
  // Calculate current month vs previous month statistics
  const calculateGrowth = () => {
    const now = new Date();
    const currentMonth = now.getMonth();
    const currentYear = now.getFullYear();
    
    // Current month data
    const currentMonthOrders = orders?.filter(order => {
      const orderDate = new Date(order.orderDate);
      return orderDate.getMonth() === currentMonth && orderDate.getFullYear() === currentYear;
    }) || [];
    
    const currentMonthUsers = users?.filter(user => {
      if (!user.createdAt) return false;
      const userDate = new Date(user.createdAt);
      return userDate.getMonth() === currentMonth && userDate.getFullYear() === currentYear;
    }) || [];
    
    // Previous month data
    const prevMonth = currentMonth === 0 ? 11 : currentMonth - 1;
    const prevYear = currentMonth === 0 ? currentYear - 1 : currentYear;
    
    const prevMonthOrders = orders?.filter(order => {
      const orderDate = new Date(order.orderDate);
      return orderDate.getMonth() === prevMonth && orderDate.getFullYear() === prevYear;
    }) || [];
    
    const prevMonthUsers = users?.filter(user => {
      if (!user.createdAt) return false;
      const userDate = new Date(user.createdAt);
      return userDate.getMonth() === prevMonth && userDate.getFullYear() === prevYear;
    }) || [];
    
    // Calculate growth percentages
    const userGrowth = prevMonthUsers.length > 0 
      ? ((currentMonthUsers.length - prevMonthUsers.length) / prevMonthUsers.length * 100).toFixed(1)
      : currentMonthUsers.length > 0 ? "100" : "0";
    
    const orderGrowth = prevMonthOrders.length > 0
      ? ((currentMonthOrders.length - prevMonthOrders.length) / prevMonthOrders.length * 100).toFixed(1)
      : currentMonthOrders.length > 0 ? "100" : "0";
    
    const currentRevenue = currentMonthOrders.reduce((sum, order) => sum + (order.totalAmount || 0), 0);
    const prevRevenue = prevMonthOrders.reduce((sum, order) => sum + (order.totalAmount || 0), 0);
    
    const revenueGrowth = prevRevenue > 0
      ? ((currentRevenue - prevRevenue) / prevRevenue * 100).toFixed(1)
      : currentRevenue > 0 ? "100" : "0";
    
    const activeUsersCount = users?.filter(u => u.status === "ACTIVE").length || 0;
    const prevActiveUsers = users?.filter(u => {
      if (!u.createdAt || u.status !== "ACTIVE") return false;
      const userDate = new Date(u.createdAt);
      return userDate.getMonth() === prevMonth && userDate.getFullYear() === prevYear;
    }).length || 0;
    
    const activeUserGrowth = prevActiveUsers > 0
      ? ((activeUsersCount - prevActiveUsers) / prevActiveUsers * 100).toFixed(1)
      : activeUsersCount > 0 ? "100" : "0";
    
    return {
      userGrowth: parseFloat(userGrowth),
      orderGrowth: parseFloat(orderGrowth),
      revenueGrowth: parseFloat(revenueGrowth),
      activeUserGrowth: parseFloat(activeUserGrowth)
    };
  };

  const growth = calculateGrowth();

  const statsCards = [
    {
      title: "Tổng người dùng",
      value: systemStats?.totalUsers || users?.length || 0,
      change: `${growth.userGrowth >= 0 ? '+' : ''}${growth.userGrowth}%`,
      changeType: growth.userGrowth >= 0 ? "positive" : "negative",
      icon: Users,
      color: "blue",
    },
    {
      title: "Người dùng hoạt động",
      value: systemStats?.activeUsers || users?.filter(u => u.status === "ACTIVE").length || 0,
      change: `${growth.activeUserGrowth >= 0 ? '+' : ''}${growth.activeUserGrowth}%`,
      changeType: growth.activeUserGrowth >= 0 ? "positive" : "negative",
      icon: Activity,
      color: "green",
    },
    {
      title: "Tổng đơn hàng",
      value: orders?.length || 0,
      change: `${growth.orderGrowth >= 0 ? '+' : ''}${growth.orderGrowth}%`,
      changeType: growth.orderGrowth >= 0 ? "positive" : "negative",
      icon: ShoppingCart,
      color: "purple",
    },
    {
      title: "Doanh thu",
      value: formatCurrency(
        orders?.reduce((sum, order) => sum + (order.totalAmount || 0), 0) || 0
      ),
      change: `${growth.revenueGrowth >= 0 ? '+' : ''}${growth.revenueGrowth}%`,
      changeType: growth.revenueGrowth >= 0 ? "positive" : "negative",
      icon: DollarSign,
      color: "yellow",
    },
  ];

  return (
    <div className="space-y-8">
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statsCards.map((stat, index) => {
          const Icon = stat.icon;
          return (
            <div
              key={index}
              className="bg-white p-6 rounded-lg shadow-sm border"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">
                    {stat.title}
                  </p>
                  <p className="text-2xl font-bold text-gray-900">
                    {stat.value}
                  </p>
                  <p
                    className={`text-xs ${
                      stat.changeType === "positive"
                        ? "text-green-600"
                        : "text-red-600"
                    }`}
                  >
                    {stat.change} từ tháng trước
                  </p>
                </div>
                <div className={`p-3 rounded-lg bg-${stat.color}-100`}>
                  <Icon className={`h-6 w-6 text-${stat.color}-600`} />
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Recent Activity Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Recent Users */}
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900">
              Người dùng gần đây
            </h3>
            <button className="text-blue-600 hover:text-blue-700 text-sm font-medium">
              Xem tất cả
            </button>
          </div>
          <div className="space-y-4">
            {users?.length > 0 ? (
              users.slice(0, 5).map((user) => (
                <div
                  key={user.id}
                  className="flex items-center justify-between"
                >
                  <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
                      <span className="text-blue-600 text-sm font-medium">
                        {user.username?.[0]?.toUpperCase() || "U"}
                      </span>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-900">
                        {user.username || "Chưa có tên"}
                      </p>
                      <p className="text-xs text-gray-500">
                        {user.email || "Chưa có email"}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <span
                      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        user.status === "ACTIVE"
                          ? "bg-green-100 text-green-800"
                          : user.status === "PENDING"
                          ? "bg-yellow-100 text-yellow-800"
                          : "bg-red-100 text-red-800"
                      }`}
                    >
                      {user.status === "ACTIVE"
                        ? "Hoạt động"
                        : user.status === "PENDING"
                        ? "Chờ duyệt"
                        : user.status === "INACTIVE"
                        ? "Không hoạt động"
                        : user.status || "Chưa rõ"}
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-4">
                <p className="text-gray-500">Chưa có người dùng nào</p>
              </div>
            )}
          </div>
        </div>

        {/* Recent Orders */}
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900">
              Đơn hàng gần đây
            </h3>
            <button className="text-blue-600 hover:text-blue-700 text-sm font-medium">
              Xem tất cả
            </button>
          </div>
          <div className="space-y-4">
            {orders?.length > 0 ? (
              orders.slice(0, 5).map((order) => (
                <div
                  key={order.id}
                  className="flex items-center justify-between"
                >
                  <div>
                    <p className="text-sm font-medium text-gray-900">
                      #{order.id}
                    </p>
                    <p className="text-xs text-gray-500">
                      {order.user?.username || "Khách hàng"}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-medium text-gray-900">
                      {formatCurrency(order.totalAmount || 0)}
                    </p>
                    <span
                      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        order.status === "DELIVERED"
                          ? "bg-green-100 text-green-800"
                          : order.status === "SHIPPED"
                          ? "bg-blue-100 text-blue-800"
                          : order.status === "PROCESSING"
                          ? "bg-yellow-100 text-yellow-800"
                          : "bg-gray-100 text-gray-800"
                      }`}
                    >
                      {order.status === "PENDING"
                        ? "Chờ xử lý"
                        : order.status === "CONFIRMED"
                        ? "Đã xác nhận"
                        : order.status === "PROCESSING"
                        ? "Đang xử lý"
                        : order.status === "SHIPPED"
                        ? "Đã gửi"
                        : order.status === "DELIVERED"
                        ? "Đã giao"
                        : order.status === "CANCELLED"
                        ? "Đã hủy"
                        : order.status || "Chưa rõ"}
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-4">
                <p className="text-gray-500">Chưa có đơn hàng nào</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* System Health */}
      <div className="bg-white p-6 rounded-lg shadow-sm border">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">
          Tình trạng hệ thống
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center">
            <div className={`w-12 h-12 ${systemStats?.databaseStatus === 'healthy' ? 'bg-green-100' : 'bg-red-100'} rounded-full mx-auto mb-2 flex items-center justify-center`}>
              {systemStats?.databaseStatus === 'healthy' ? (
                <CheckCircle className="h-6 w-6 text-green-600" />
              ) : (
                <AlertTriangle className="h-6 w-6 text-red-600" />
              )}
            </div>
            <p className="text-sm font-medium text-gray-900">Cơ sở dữ liệu</p>
            <p className={`text-xs ${systemStats?.databaseStatus === 'healthy' ? 'text-green-600' : 'text-red-600'}`}>
              {systemStats?.databaseStatus === 'healthy' ? 'Tốt' : 'Lỗi'}
            </p>
          </div>
          <div className="text-center">
            <div className="w-12 h-12 bg-green-100 rounded-full mx-auto mb-2 flex items-center justify-center">
              <CheckCircle className="h-6 w-6 text-green-600" />
            </div>
            <p className="text-sm font-medium text-gray-900">API</p>
            <p className="text-xs text-green-600">Hoạt động</p>
          </div>
          <div className="text-center">
            <div className={`w-12 h-12 ${(systemStats?.storageUsage || 0) > 90 ? 'bg-red-100' : (systemStats?.storageUsage || 0) > 80 ? 'bg-yellow-100' : 'bg-green-100'} rounded-full mx-auto mb-2 flex items-center justify-center`}>
              {(systemStats?.storageUsage || 0) > 90 ? (
                <AlertTriangle className="h-6 w-6 text-red-600" />
              ) : (systemStats?.storageUsage || 0) > 80 ? (
                <AlertTriangle className="h-6 w-6 text-yellow-600" />
              ) : (
                <CheckCircle className="h-6 w-6 text-green-600" />
              )}
            </div>
            <p className="text-sm font-medium text-gray-900">Lưu trữ</p>
            <p className={`text-xs ${(systemStats?.storageUsage || 0) > 90 ? 'text-red-600' : (systemStats?.storageUsage || 0) > 80 ? 'text-yellow-600' : 'text-green-600'}`}>
              Đã dùng {systemStats?.storageUsage || 0}%
            </p>
          </div>
          <div className="text-center">
            <div className={`w-12 h-12 ${systemStats?.cacheStatus === 'healthy' ? 'bg-green-100' : 'bg-yellow-100'} rounded-full mx-auto mb-2 flex items-center justify-center`}>
              {systemStats?.cacheStatus === 'healthy' ? (
                <CheckCircle className="h-6 w-6 text-green-600" />
              ) : (
                <AlertTriangle className="h-6 w-6 text-yellow-600" />
              )}
            </div>
            <p className="text-sm font-medium text-gray-900">Cache</p>
            <p className={`text-xs ${systemStats?.cacheStatus === 'healthy' ? 'text-green-600' : 'text-yellow-600'}`}>
              {systemStats?.cacheStatus === 'healthy' ? 'Tốt' : 'Cảnh báo'}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdminDashboard;
