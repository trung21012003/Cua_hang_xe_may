import React, { useState } from "react";
import axios from "axios";
import {
  Users,
  Package,
  ShoppingCart,
  TrendingUp,
  Settings,
  Search,
  Filter,
  Plus,
  Edit,
  Trash2,
  Eye,
  BarChart3,
  PieChart,
  RefreshCw,
  Download,
  Bell,
  Calendar,
  DollarSign,
  Activity,
  AlertTriangle,
  CheckCircle,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  MoreHorizontal,
  X,
  Zap,
} from "lucide-react";

// Users Tab Component
export const UsersTab = ({
  users,
  userFilter,
  setUserFilter,
  userPage,
  setUserPage,
  updateUserRole,
  updateUserStatus,
  deleteUser,
  getRoleDisplayName,
  formatDate,
  fetchUsers,
}) => {
  const [selectedUsers, setSelectedUsers] = useState([]);
  const [showUserModal, setShowUserModal] = useState(false);
  const [showAddUserModal, setShowAddUserModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [modalMode, setModalMode] = useState("view"); // 'view', 'edit', 'add'
  const [roleFilter, setRoleFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [newUser, setNewUser] = useState({
    username: "",
    email: "",
    password: "",
    phone: "",
    name: "",
    address: "",
    role: "1",
    status: "ACTIVE",
  });

  const filteredUsers = Array.isArray(users)
    ? users.filter((user) => {
        const matchesSearch =
          user.username?.toLowerCase().includes(userFilter.toLowerCase()) ||
          user.email?.toLowerCase().includes(userFilter.toLowerCase());
        const matchesRole = roleFilter === "all" || user.role === roleFilter;
        const matchesStatus =
          statusFilter === "all" || user.status === statusFilter;

        return matchesSearch && matchesRole && matchesStatus;
      })
    : [];

  const handleAddUser = async () => {
    try {
      const token = localStorage.getItem("jwtToken");
      await axios.post("http://localhost:8080/api/admin/users", newUser, {
        headers: { Authorization: `Bearer ${token}` },
      });
      alert("Thêm người dùng thành công!");
      setShowAddUserModal(false);
      setNewUser({
        username: "",
        email: "",
        password: "",
        phone: "",
        name: "",
        address: "",
        role: "1",
        status: "ACTIVE",
      });
      fetchUsers();
    } catch (error) {
      console.error("Error adding user:", error);
      alert(
        "Lỗi khi thêm người dùng: " +
          (error.response?.data?.message || error.message)
      );
    }
  };

  const handleViewUser = (user) => {
    setSelectedUser(user);
    setModalMode("view");
    setShowUserModal(true);
  };

  const handleEditUser = (user) => {
    setSelectedUser(user);
    setModalMode("edit");
    setShowUserModal(true);
  };

  const handleSaveUser = async () => {
    try {
      const token = localStorage.getItem("jwtToken");
      await axios.put(
        `http://localhost:8080/api/admin/users/${selectedUser.id}`,
        selectedUser,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      alert("Cập nhật người dùng thành công!");
      setShowUserModal(false);
      fetchUsers();
    } catch (error) {
      console.error("Error updating user:", error);
      alert(
        "Lỗi khi cập nhật người dùng: " +
          (error.response?.data?.message || error.message)
      );
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">
            Quản lý người dùng
          </h2>
          <p className="text-gray-600">
            Quản lý tài khoản người dùng, vai trò và quyền hạn
          </p>
        </div>
        <div className="flex space-x-3">
          <button className="flex items-center px-4 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50">
            <Download className="h-4 w-4 mr-2" />
            Xuất dữ liệu
          </button>
          <button
            onClick={() => setShowAddUserModal(true)}
            className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            <Plus className="h-4 w-4 mr-2" />
            Thêm người dùng
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white p-4 rounded-lg shadow-sm border">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
            <input
              type="text"
              placeholder="Tìm kiếm người dùng theo tên hoặc email..."
              className="pl-10 pr-4 py-2 w-full border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
              value={userFilter}
              onChange={(e) => setUserFilter(e.target.value)}
            />
          </div>
          <div className="flex space-x-2">
            <select
              value={roleFilter}
              onChange={(e) => setRoleFilter(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">Tất cả vai trò</option>
              <option value="0">Quản trị viên</option>
              <option value="1">Người dùng</option>
              <option value="2">Quản lý</option>
              <option value="3">Khách</option>
            </select>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">Tất cả trạng thái</option>
              <option value="ACTIVE">Hoạt động</option>
              <option value="PENDING">Chờ duyệt</option>
              <option value="INACTIVE">Không hoạt động</option>
            </select>
          </div>
        </div>
      </div>

      {/* Users Table */}
      <div className="bg-white rounded-lg shadow-sm border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  <input type="checkbox" className="rounded border-gray-300" />
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Người dùng
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Vai trò
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Trạng thái
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Ngày tạo
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Thao tác
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredUsers.map((user) => (
                <tr key={user.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <input
                      type="checkbox"
                      className="rounded border-gray-300"
                    />
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center">
                        <span className="text-blue-600 font-medium">
                          {user.username?.[0]?.toUpperCase() || "U"}
                        </span>
                      </div>
                      <div className="ml-4">
                        <div className="text-sm font-medium text-gray-900">
                          {user.username}
                        </div>
                        <div className="text-sm text-gray-500">
                          {user.email}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <select
                      value={user.role}
                      onChange={(e) => updateUserRole(user.id, e.target.value)}
                      className="text-sm border border-gray-300 rounded px-2 py-1 focus:ring-blue-500 focus:border-blue-500"
                    >
                      <option value="0">Quản trị viên</option>
                      <option value="1">Người dùng</option>
                      <option value="2">Quản lý</option>
                      <option value="3">Khách</option>
                    </select>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <select
                      value={user.status}
                      onChange={(e) =>
                        updateUserStatus(user.id, e.target.value)
                      }
                      className={`text-sm border rounded px-2 py-1 focus:ring-blue-500 focus:border-blue-500 ${
                        user.status === "ACTIVE"
                          ? "bg-green-50 border-green-200 text-green-800"
                          : user.status === "PENDING"
                          ? "bg-yellow-50 border-yellow-200 text-yellow-800"
                          : "bg-red-50 border-red-200 text-red-800"
                      }`}
                    >
                      <option value="ACTIVE">Hoạt động</option>
                      <option value="PENDING">Chờ duyệt</option>
                      <option value="INACTIVE">Không hoạt động</option>
                    </select>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {formatDate(user.created)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <div className="flex space-x-2">
                      <button
                        onClick={() => handleViewUser(user)}
                        className="text-blue-600 hover:text-blue-900"
                        title="Xem chi tiết"
                      >
                        <Eye className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => handleEditUser(user)}
                        className="text-gray-600 hover:text-gray-900"
                        title="Chỉnh sửa"
                      >
                        <Edit className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => deleteUser(user.id)}
                        className="text-red-600 hover:text-red-900"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="bg-white px-4 py-3 flex items-center justify-between border-t border-gray-200 sm:px-6">
          <div className="flex-1 flex justify-between sm:hidden">
            <button className="relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
              Trước
            </button>
            <button className="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
              Sau
            </button>
          </div>
          <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
            <div>
              <p className="text-sm text-gray-700">
                Hiển thị <span className="font-medium">1</span> đến{" "}
                <span className="font-medium">10</span> trong{" "}
                <span className="font-medium">{filteredUsers.length}</span> kết
                quả
              </p>
            </div>
            <div>
              <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px">
                <button className="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50">
                  <ChevronLeft className="h-5 w-5" />
                </button>
                <button className="relative inline-flex items-center px-4 py-2 border border-gray-300 bg-white text-sm font-medium text-gray-700 hover:bg-gray-50">
                  1
                </button>
                <button className="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50">
                  <ChevronRight className="h-5 w-5" />
                </button>
              </nav>
            </div>
          </div>
        </div>
      </div>

      {/* Add User Modal */}
      {showAddUserModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg w-full max-w-2xl max-h-[90vh] flex flex-col">
            <div className="flex justify-between items-center p-6 border-b">
              <h3 className="text-lg font-semibold text-gray-900">
                Thêm người dùng mới
              </h3>
              <button
                onClick={() => setShowAddUserModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 space-y-0">
                                <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Tên người dùng
                    </label>
                    <input
                      type="text"
                      value={newUser.username}
                      onChange={(e) =>
                        setNewUser({ ...newUser, username: e.target.value })
                      }
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                      placeholder="Nhập tên người dùng"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Email
                    </label>
                    <input
                      type="email"
                      value={newUser.email}
                      onChange={(e) =>
                        setNewUser({ ...newUser, email: e.target.value })
                      }
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                      placeholder="Nhập email"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Mật khẩu
                    </label>
                    <input
                      type="password"
                      value={newUser.password}
                      onChange={(e) =>
                        setNewUser({ ...newUser, password: e.target.value })
                      }
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                      placeholder="Nhập mật khẩu"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Họ và tên
                    </label>
                    <input
                      type="text"
                      value={newUser.name}
                      onChange={(e) =>
                        setNewUser({ ...newUser, name: e.target.value })
                      }
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                      placeholder="Nhập họ và tên"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Số điện thoại
                    </label>
                    <input
                      type="tel"
                      value={newUser.phone}
                      onChange={(e) =>
                        setNewUser({ ...newUser, phone: e.target.value })
                      }
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                      placeholder="Nhập số điện thoại"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Địa chỉ
                    </label>
                    <input
                      type="text"
                      value={newUser.address}
                      onChange={(e) =>
                        setNewUser({ ...newUser, address: e.target.value })
                      }
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                      placeholder="Nhập địa chỉ"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Vai trò
                    </label>
                    <select
                      value={newUser.role}
                      onChange={(e) =>
                        setNewUser({ ...newUser, role: e.target.value })
                      }
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                    >
                      <option value="1">Người dùng</option>
                      <option value="0">Quản trị viên</option>
                      <option value="2">Quản lý</option>
                      <option value="3">Khách</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Trạng thái
                    </label>
                    <select
                      value={newUser.status}
                      onChange={(e) =>
                        setNewUser({ ...newUser, status: e.target.value })
                      }
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                    >
                      <option value="ACTIVE">Hoạt động</option>
                      <option value="PENDING">Chờ duyệt</option>
                      <option value="INACTIVE">Không hoạt động</option>
                    </select>
                  </div>
            </div>

                </div>
              </div>

              <div className="border-t p-6">
                <div className="flex justify-end space-x-3">
                  <button
                    onClick={() => setShowAddUserModal(false)}
                    className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50"
                  >
                    Hủy
                  </button>
                                    <button
                    onClick={handleAddUser}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                  >
                    Thêm người dùng
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* View/Edit User Modal */}
        {showUserModal && selectedUser && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-lg w-full max-w-2xl max-h-[90vh] flex flex-col">
              <div className="flex justify-between items-center p-6 border-b">
                <h3 className="text-lg font-semibold text-gray-900">
                  {modalMode === "view"
                    ? "Chi tiết người dùng"
                    : "Chỉnh sửa người dùng"}
                </h3>
                <button
                  onClick={() => setShowUserModal(false)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              <div className="flex-1 overflow-y-auto p-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 space-y-0">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Tên người dùng
                  </label>
                  <input
                    type="text"
                    value={selectedUser.username}
                    onChange={(e) =>
                      setSelectedUser({
                        ...selectedUser,
                        username: e.target.value,
                      })
                    }
                    disabled={modalMode === "view"}
                    className={`w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 ${
                      modalMode === "view" ? "bg-gray-50" : ""
                    }`}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Email
                  </label>
                  <input
                    type="email"
                    value={selectedUser.email}
                    onChange={(e) =>
                      setSelectedUser({ ...selectedUser, email: e.target.value })
                    }
                    disabled={modalMode === "view"}
                    className={`w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 ${
                      modalMode === "view" ? "bg-gray-50" : ""
                    }`}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Vai trò
                  </label>
                  <select
                    value={selectedUser.role}
                    onChange={(e) =>
                      setSelectedUser({ ...selectedUser, role: e.target.value })
                    }
                    disabled={modalMode === "view"}
                    className={`w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 ${
                      modalMode === "view" ? "bg-gray-50" : ""
                    }`}
                  >
                    <option value="0">Quản trị viên</option>
                    <option value="1">Người dùng</option>
                    <option value="2">Quản lý</option>
                    <option value="3">Khách</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Trạng thái
                  </label>
                  <select
                    value={selectedUser.status}
                    onChange={(e) =>
                      setSelectedUser({ ...selectedUser, status: e.target.value })
                    }
                    disabled={modalMode === "view"}
                    className={`w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 ${
                      modalMode === "view" ? "bg-gray-50" : ""
                    }`}
                  >
                    <option value="ACTIVE">Hoạt động</option>
                    <option value="PENDING">Chờ duyệt</option>
                    <option value="INACTIVE">Không hoạt động</option>
                  </select>
                </div>

                {modalMode === "view" && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Ngày tạo
                    </label>
                    <input
                      type="text"
                      value={formatDate(selectedUser.created)}
                      disabled
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg bg-gray-50"
                    />
                  </div>
                )}
                </div>
              </div>

              <div className="border-t p-6">
                <div className="flex justify-end space-x-3">
                  <button
                    onClick={() => setShowUserModal(false)}
                    className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50"
                  >
                    {modalMode === "view" ? "Đóng" : "Hủy"}
                  </button>
                  {modalMode === "view" ? (
                    <button
                      onClick={() => setModalMode("edit")}
                      className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                    >
                      Chỉnh sửa
                    </button>
                  ) : (
                    <button
                      onClick={handleSaveUser}
                      className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
                    >
                      Lưu thay đổi
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
    </div>
  );
};

// Orders Tab Component
export const OrdersTab = ({
  orders,
  orderFilter,
  setOrderFilter,
  orderPage,
  setOrderPage,
  updateOrderStatus,
  formatCurrency,
  formatDate,
}) => {
  const [selectedOrders, setSelectedOrders] = useState([]);
  const [showOrderModal, setShowOrderModal] = useState(false);
  const [selectedOrder, setSelectedOrder] = useState(null);

  const statusColors = {
    PENDING: "bg-yellow-100 text-yellow-800",
    CONFIRMED: "bg-blue-100 text-blue-800",
    PROCESSING: "bg-purple-100 text-purple-800",
    SHIPPED: "bg-indigo-100 text-indigo-800",
    DELIVERED: "bg-green-100 text-green-800",
    CANCELLED: "bg-red-100 text-red-800",
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Quản lý đơn hàng</h2>
          <p className="text-gray-600">
            Theo dõi và quản lý đơn hàng khách hàng
          </p>
        </div>
        <div className="flex space-x-3">
          <button className="flex items-center px-4 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50">
            <Download className="h-4 w-4 mr-2" />
            Xuất dữ liệu
          </button>
          <button className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
            <Plus className="h-4 w-4 mr-2" />
            Tạo đơn thủ công
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 rounded">
              <ShoppingCart className="h-6 w-6 text-blue-600" />
            </div>
            <div className="ml-3">
              <p className="text-sm font-medium text-gray-600">Tổng đơn hàng</p>
              <p className="text-2xl font-bold text-gray-900">
                {orders?.length || 0}
              </p>
            </div>
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <div className="flex items-center">
            <div className="p-2 bg-yellow-100 rounded">
              <Calendar className="h-6 w-6 text-yellow-600" />
            </div>
            <div className="ml-3">
              <p className="text-sm font-medium text-gray-600">Chờ xử lý</p>
              <p className="text-2xl font-bold text-gray-900">
                {orders?.filter((o) => o.status === "PENDING").length || 0}
              </p>
            </div>
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <div className="flex items-center">
            <div className="p-2 bg-green-100 rounded">
              <CheckCircle className="h-6 w-6 text-green-600" />
            </div>
            <div className="ml-3">
              <p className="text-sm font-medium text-gray-600">Đã giao</p>
              <p className="text-2xl font-bold text-gray-900">
                {orders?.filter((o) => o.status === "DELIVERED").length || 0}
              </p>
            </div>
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <div className="flex items-center">
            <div className="p-2 bg-purple-100 rounded">
              <DollarSign className="h-6 w-6 text-purple-600" />
            </div>
            <div className="ml-3">
              <p className="text-sm font-medium text-gray-600">Doanh thu</p>
              <p className="text-2xl font-bold text-gray-900">
                {formatCurrency(
                  orders?.reduce(
                    (sum, order) => sum + (order.totalAmount || 0),
                    0
                  ) || 0
                )}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white p-4 rounded-lg shadow-sm border">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
            <input
              type="text"
              placeholder="Tìm kiếm đơn hàng theo ID hoặc khách hàng..."
              className="pl-10 pr-4 py-2 w-full border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          <div className="flex space-x-2">
            <select
              value={orderFilter}
              onChange={(e) => setOrderFilter(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">Tất cả trạng thái</option>
              <option value="PENDING">Chờ xử lý</option>
              <option value="CONFIRMED">Đã xác nhận</option>
              <option value="PROCESSING">Đang xử lý</option>
              <option value="SHIPPED">Đã gửi</option>
              <option value="DELIVERED">Đã giao</option>
              <option value="CANCELLED">Đã hủy</option>
            </select>
            <select className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500">
              <option value="today">Hôm nay</option>
              <option value="week">Tuần này</option>
              <option value="month">Tháng này</option>
              <option value="all">Tất cả</option>
            </select>
          </div>
        </div>
      </div>

      {/* Orders Table */}
      <div className="bg-white rounded-lg shadow-sm border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Mã đơn hàng
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Khách hàng
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Số tiền
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Trạng thái
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Ngày
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Thao tác
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {orders?.map((order) => (
                <tr key={order.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-medium text-gray-900">
                      #{order.id}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="w-8 h-8 bg-gray-100 rounded-full flex items-center justify-center">
                        <span className="text-gray-600 text-sm font-medium">
                          {order.user?.username?.[0]?.toUpperCase() || "U"}
                        </span>
                      </div>
                      <div className="ml-3">
                        <div className="text-sm font-medium text-gray-900">
                          {order.user?.username || "Không rõ"}
                        </div>
                        <div className="text-sm text-gray-500">
                          {order.shippingPhone || "Chưa có SĐT"}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-medium text-gray-900">
                      {formatCurrency(order.totalAmount)}
                    </div>
                    <div className="text-sm text-gray-500">
                      {order.paymentMethod || "Chưa rõ"}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <select
                      value={order.status}
                      onChange={(e) =>
                        updateOrderStatus(order.id, e.target.value)
                      }
                      className={`text-sm border rounded px-2 py-1 focus:ring-blue-500 focus:border-blue-500 ${
                        statusColors[order.status] ||
                        "bg-gray-100 text-gray-800"
                      }`}
                    >
                      <option value="PENDING">Chờ xử lý</option>
                      <option value="CONFIRMED">Đã xác nhận</option>
                      <option value="PROCESSING">Đang xử lý</option>
                      <option value="SHIPPED">Đã gửi</option>
                      <option value="DELIVERED">Đã giao</option>
                      <option value="CANCELLED">Đã hủy</option>
                    </select>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {formatDate(order.orderDate)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <div className="flex space-x-2">
                      <button
                        onClick={() => setSelectedOrder(order)}
                        className="text-blue-600 hover:text-blue-900"
                      >
                        <Eye className="h-4 w-4" />
                      </button>
                      <button className="text-gray-600 hover:text-gray-900">
                        <MoreHorizontal className="h-4 w-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

// Products Tab Component
export const ProductsTab = ({
  products,
  formatCurrency,
  formatDate,
  fetchProducts,
}) => {
  const [productFilter, setProductFilter] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [brandFilter, setBrandFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [showAddProductModal, setShowAddProductModal] = useState(false);
  const [showProductModal, setShowProductModal] = useState(false);
  const [selectedProduct, setSelectedProduct] = useState(null);
  const [modalMode, setModalMode] = useState("view"); // 'view', 'edit', 'add'
  const [expandedSpecs, setExpandedSpecs] = useState({});
  const [activeTab, setActiveTab] = useState("basic");
  const [newProduct, setNewProduct] = useState({
    name: "",
    description: "",
    price: "",
    brandName: "",
    motolineName: "",
    status: "ACTIVE",
    avatar: "",
    // Technical specs
    weight: "",
    size: "",
    petrolCapacity: "",
    saddleHeight: "",
    wheelSize: "",
    beforeFork: "",
    afterFork: "",
    maxiumCapacity: "",
    oilCapacity: "",
    fuelConsumption: "",
    cylinderCapacity: "",
    maxiumMoment: "",
    compressionRatio: "",
    engieType: "",
  });

  // Helper function to check if product is active
  const isProductActive = (status) => {
    // If status is undefined/null, consider product as active by default
    return (
      status === "ACTIVE" ||
      status === true ||
      status === 1 ||
      status === undefined ||
      status === null
    );
  };

  const filteredProducts = Array.isArray(products)
    ? products.filter((product) => {
        const matchesSearch =
          product.name?.toLowerCase().includes(productFilter.toLowerCase()) ||
          product.description
            ?.toLowerCase()
            .includes(productFilter.toLowerCase());
        const matchesCategory =
          categoryFilter === "all" || product.motolineName === categoryFilter;
        const matchesBrand =
          brandFilter === "all" || product.brandName === brandFilter;

        // Handle different status formats from backend
        let matchesStatus = false;
        if (statusFilter === "all") {
          matchesStatus = true;
        } else if (statusFilter === "ACTIVE") {
          matchesStatus = isProductActive(product.status);
        } else if (statusFilter === "INACTIVE") {
          matchesStatus = !isProductActive(product.status);
        }

        return (
          matchesSearch && matchesCategory && matchesBrand && matchesStatus
        );
      })
    : [];

  // Get unique categories and brands for filters
  const categories = [
    ...new Set(products?.map((p) => p.motolineName).filter(Boolean)),
  ];
  const brands = [
    ...new Set(products?.map((p) => p.brandName).filter(Boolean)),
  ];

  // Helper functions
  const toggleSpecs = (productId) => {
    setExpandedSpecs((prev) => ({
      ...prev,
      [productId]: !prev[productId],
    }));
  };

  const getStockStatus = (product) => {
    const totalStock = product.totalStock || 0;
    if (totalStock === 0) return { text: "Hết hàng", color: "red" };
    if (totalStock < 10) return { text: "Sắp hết", color: "yellow" };
    return { text: "Còn hàng", color: "green" };
  };

  const handleAddProduct = async () => {
    try {
      const token = localStorage.getItem("jwtToken");
      await axios.post(
        "http://localhost:8080/api/products/manage",
        newProduct,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      alert("Thêm sản phẩm thành công!");
      setShowAddProductModal(false);
      setNewProduct({
        name: "",
        description: "",
        price: "",
        brandName: "",
        motolineName: "",
        status: "ACTIVE",
        avatar: "",
        weight: "",
        size: "",
        petrolCapacity: "",
        saddleHeight: "",
        wheelSize: "",
        beforeFork: "",
        afterFork: "",
        maxiumCapacity: "",
        oilCapacity: "",
        fuelConsumption: "",
        cylinderCapacity: "",
        maxiumMoment: "",
        compressionRatio: "",
        engieType: "",
      });
      fetchProducts && fetchProducts();
    } catch (error) {
      console.error("Error adding product:", error);
      alert(
        "Lỗi khi thêm sản phẩm: " +
          (error.response?.data?.message || error.message)
      );
    }
  };

  const handleViewProduct = (product) => {
    setSelectedProduct(product);
    setModalMode("view");
    setShowProductModal(true);
  };

  const handleEditProduct = (product) => {
    setSelectedProduct(product);
    setModalMode("edit");
    setShowProductModal(true);
  };

  const handleSaveProduct = async () => {
    try {
      const token = localStorage.getItem("jwtToken");
      await axios.put(
        `http://localhost:8080/api/products/manage/${selectedProduct.id}`,
        selectedProduct,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      alert("Cập nhật sản phẩm thành công!");
      setShowProductModal(false);
      fetchProducts && fetchProducts();
    } catch (error) {
      console.error("Error updating product:", error);
      alert(
        "Lỗi khi cập nhật sản phẩm: " +
          (error.response?.data?.message || error.message)
      );
    }
  };

  const handleDeleteProduct = async (productId) => {
    if (
      !confirm(
        "Bạn có chắc chắn muốn xóa sản phẩm này? Hành động này không thể hoàn tác."
      )
    ) {
      return;
    }

    try {
      const token = localStorage.getItem("jwtToken");
      await axios.delete(
        `http://localhost:8080/api/products/manage/${productId}`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      alert("Xóa sản phẩm thành công!");
      fetchProducts && fetchProducts();
    } catch (error) {
      console.error("Error deleting product:", error);
      alert(
        "Lỗi khi xóa sản phẩm: " +
          (error.response?.data?.message || error.message)
      );
    }
  };

  const handleExportData = () => {
    try {
      const csvContent = [
        [
          "ID",
          "Tên sản phẩm",
          "Mô tả",
          "Giá",
          "Thương hiệu",
          "Danh mục",
          "Trạng thái",
        ],
        ...filteredProducts.map((product) => [
          product.id,
          product.name,
          product.description,
          product.price,
          product.brandName,
          product.categoryName,
          product.status,
        ]),
      ]
        .map((row) => row.join(","))
        .join("\n");

      const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `products_export_${
        new Date().toISOString().split("T")[0]
      }.csv`;
      link.click();
      alert("Xuất dữ liệu thành công!");
    } catch (error) {
      console.error("Error exporting data:", error);
      alert("Lỗi khi xuất dữ liệu: " + error.message);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Quản lý sản phẩm</h2>
          <p className="text-gray-600">Quản lý danh mục sản phẩm của bạn</p>
        </div>
        <div className="flex space-x-3">
          <button
            onClick={handleExportData}
            className="flex items-center px-4 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50"
          >
            <Download className="h-4 w-4 mr-2" />
            Xuất dữ liệu
          </button>
          <button
            onClick={() => setShowAddProductModal(true)}
            className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            <Plus className="h-4 w-4 mr-2" />
            Thêm sản phẩm
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white p-4 rounded-lg shadow-sm border">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="relative">
            <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
            <input
              type="text"
              placeholder="Tìm kiếm sản phẩm..."
              className="pl-10 pr-4 py-2 w-full border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
              value={productFilter}
              onChange={(e) => setProductFilter(e.target.value)}
            />
          </div>

          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="all">Tất cả danh mục</option>
            {categories.map((category) => (
              <option key={category} value={category}>
                {category}
              </option>
            ))}
          </select>

          <select
            value={brandFilter}
            onChange={(e) => setBrandFilter(e.target.value)}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="all">Tất cả thương hiệu</option>
            {brands.map((brand) => (
              <option key={brand} value={brand}>
                {brand}
              </option>
            ))}
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="all">Tất cả trạng thái</option>
            <option value="ACTIVE">Hoạt động</option>
            <option value="INACTIVE">Không hoạt động</option>
          </select>
        </div>
      </div>

      {/* Products Grid - Enhanced */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        {filteredProducts.length > 0 ? (
          filteredProducts.map((product) => {
            const stockStatus = getStockStatus(product);
            const isExpanded = expandedSpecs[product.id];

            return (
              <div
                key={product.id}
                className="bg-white rounded-lg shadow-sm border overflow-hidden"
              >
                {/* Product Image with Stock Badge */}
                <div className="relative">
                  <img
                    src={
                      product.avatar
                        ? `http://localhost:8080/api/files/${product.avatar}`
                        : "/api/placeholder/400/300"
                    }
                    alt={product.name}
                    className="w-full h-48 object-cover"
                  />
                  <div className="absolute top-2 right-2">
                    <span
                      className={`px-2 py-1 rounded-full text-xs font-medium ${
                        stockStatus.color === "green"
                          ? "bg-green-100 text-green-800"
                          : stockStatus.color === "yellow"
                          ? "bg-yellow-100 text-yellow-800"
                          : "bg-red-100 text-red-800"
                      }`}
                    >
                      {stockStatus.text}
                    </span>
                  </div>
                </div>

                {/* Product Info */}
                <div className="p-6">
                  <div className="flex items-start justify-between mb-2">
                    <h3 className="text-lg font-semibold text-gray-900 line-clamp-2">
                      {product.name}
                    </h3>
                    <span className="text-sm text-gray-500 ml-2">
                      #{product.id}
                    </span>
                  </div>

                  <p className="text-gray-600 text-sm mb-3 line-clamp-2">
                    {product.description}
                  </p>

                  <div className="flex items-center justify-between mb-3">
                    <span className="text-2xl font-bold text-blue-600">
                      {formatCurrency(product.price)}
                    </span>
                    <div className="text-right text-sm">
                      <div className="text-gray-500">Thương hiệu</div>
                      <div className="font-medium">{product.brandName}</div>
                    </div>
                  </div>

                  {/* Quick specs */}
                  <div className="grid grid-cols-2 gap-2 mb-4 text-sm">
                    <div className="flex items-center space-x-2">
                      <Settings className="h-4 w-4 text-gray-400" />
                      <span>{product.engieType || "N/A"}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Zap className="h-4 w-4 text-gray-400" />
                      <span>{product.fuelConsumption || "N/A"}</span>
                    </div>
                  </div>

                  {/* Expanded specs */}
                  {isExpanded && (
                    <div className="mb-4 p-3 bg-gray-50 rounded-lg">
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <div>
                          <strong>Trọng lượng:</strong>{" "}
                          {product.weight || "N/A"}
                        </div>
                        <div>
                          <strong>Kích thước:</strong> {product.size || "N/A"}
                        </div>
                        <div>
                          <strong>Dung tích bình xăng:</strong>{" "}
                          {product.petrolCapacity || "N/A"}
                        </div>
                        <div>
                          <strong>Chiều cao yên:</strong>{" "}
                          {product.saddleHeight || "N/A"}
                        </div>
                        <div>
                          <strong>Kích thước bánh:</strong>{" "}
                          {product.wheelSize || "N/A"}
                        </div>
                        <div>
                          <strong>Dung tích xi lanh:</strong>{" "}
                          {product.cylinderCapacity || "N/A"}
                        </div>
                      </div>
                    </div>
                  )}

                  <button
                    onClick={() => toggleSpecs(product.id)}
                    className="w-full text-center text-sm text-blue-600 hover:text-blue-700 mb-4 flex items-center justify-center space-x-1"
                  >
                    {isExpanded ? (
                      <ChevronDown className="h-4 w-4" />
                    ) : (
                      <ChevronRight className="h-4 w-4" />
                    )}
                    <span>
                      {isExpanded ? "Thu gọn" : "Xem thông số kỹ thuật"}
                    </span>
                  </button>

                  {/* Versions & Colors Preview */}
                  {product.versionColors &&
                    product.versionColors.length > 0 && (
                      <div className="mb-4">
                        <div className="text-sm text-gray-600 mb-2">
                          {product.versionColors.length} phiên bản
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {product.versionColors.slice(0, 3).map((version) => (
                            <span
                              key={version.id}
                              className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs"
                            >
                              {version.versionName}
                            </span>
                          ))}
                          {product.versionColors.length > 3 && (
                            <span className="text-xs text-gray-500">
                              +{product.versionColors.length - 3} khác
                            </span>
                          )}
                        </div>
                      </div>
                    )}

                  {/* Actions */}
                  <div className="flex items-center justify-between">
                    <div className="flex space-x-2">
                      <button
                        onClick={() => handleViewProduct(product)}
                        className="p-2 text-gray-600 hover:text-blue-600 hover:bg-blue-50 rounded"
                        title="Xem chi tiết"
                      >
                        <Eye className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => handleEditProduct(product)}
                        className="p-2 text-gray-600 hover:text-yellow-600 hover:bg-yellow-50 rounded"
                        title="Chỉnh sửa"
                      >
                        <Edit className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => handleDeleteProduct(product.id)}
                        className="p-2 text-gray-600 hover:text-red-600 hover:bg-red-50 rounded"
                        title="Xóa"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>

                    <div className="text-right text-sm">
                      <div className="text-gray-500">Tồn kho</div>
                      <div className="font-medium">
                        {product.totalStock || 0}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            );
          })
        ) : (
          <div className="col-span-full text-center py-12">
            <Package className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <p className="text-xl text-gray-600 mb-2">
              Không tìm thấy sản phẩm nào
            </p>
            <p className="text-gray-500">
              Thử thay đổi bộ lọc hoặc thêm sản phẩm mới
            </p>
          </div>
        )}
      </div>

      {/* Add Product Modal - Enhanced */}
      {showAddProductModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg w-full max-w-4xl max-h-[90vh] overflow-hidden">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-6 border-b">
              <h2 className="text-xl font-semibold">Thêm sản phẩm mới</h2>
              <button
                onClick={() => setShowAddProductModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="h-6 w-6" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="flex-1 overflow-y-auto">
              {/* Tabs */}
              <div className="border-b">
                <nav className="flex space-x-8 px-6">
                  {[
                    { id: "basic", name: "Thông tin cơ bản" },
                    { id: "specs", name: "Thông số kỹ thuật" },
                  ].map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={`py-4 px-1 border-b-2 font-medium text-sm ${
                        activeTab === tab.id
                          ? "border-blue-500 text-blue-600"
                          : "border-transparent text-gray-500 hover:text-gray-700"
                      }`}
                    >
                      {tab.name}
                    </button>
                  ))}
                </nav>
              </div>

              {/* Tab Content */}
              <div className="p-6">
                {activeTab === "basic" && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                          Tên sản phẩm
                        </label>
                        <input
                          type="text"
                          value={newProduct.name}
                          onChange={(e) =>
                            setNewProduct({
                              ...newProduct,
                              name: e.target.value,
                            })
                          }
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                          placeholder="Nhập tên sản phẩm"
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                          Mô tả
                        </label>
                        <textarea
                          value={newProduct.description}
                          onChange={(e) =>
                            setNewProduct({
                              ...newProduct,
                              description: e.target.value,
                            })
                          }
                          rows={4}
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                          placeholder="Nhập mô tả sản phẩm"
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                          Giá (VND)
                        </label>
                        <input
                          type="number"
                          value={newProduct.price}
                          onChange={(e) =>
                            setNewProduct({
                              ...newProduct,
                              price: e.target.value,
                            })
                          }
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                          placeholder="Nhập giá sản phẩm"
                        />
                        {newProduct.price && (
                          <p className="text-sm text-gray-600 mt-1">
                            {formatCurrency(newProduct.price)}
                          </p>
                        )}
                      </div>
                    </div>

                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                          Thương hiệu
                        </label>
                        <input
                          type="text"
                          value={newProduct.brandName}
                          onChange={(e) =>
                            setNewProduct({
                              ...newProduct,
                              brandName: e.target.value,
                            })
                          }
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                          placeholder="Nhập thương hiệu"
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                          Dòng xe
                        </label>
                        <input
                          type="text"
                          value={newProduct.motolineName}
                          onChange={(e) =>
                            setNewProduct({
                              ...newProduct,
                              motolineName: e.target.value,
                            })
                          }
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                          placeholder="Nhập dòng xe"
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                          Trạng thái
                        </label>
                        <select
                          value={newProduct.status}
                          onChange={(e) =>
                            setNewProduct({
                              ...newProduct,
                              status: e.target.value,
                            })
                          }
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                        >
                          <option value="ACTIVE">Đang bán</option>
                          <option value="INACTIVE">Ngừng bán</option>
                          <option value="OUT_OF_STOCK">Hết hàng</option>
                        </select>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                          Hình ảnh
                        </label>
                        <input
                          type="text"
                          value={newProduct.avatar}
                          onChange={(e) =>
                            setNewProduct({
                              ...newProduct,
                              avatar: e.target.value,
                            })
                          }
                          placeholder="URL hình ảnh"
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                        />
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === "specs" && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {[
                      { key: "weight", label: "Trọng lượng", unit: "kg" },
                      { key: "size", label: "Kích thước", unit: "mm" },
                      {
                        key: "petrolCapacity",
                        label: "Dung tích bình xăng",
                        unit: "lít",
                      },
                      {
                        key: "saddleHeight",
                        label: "Chiều cao yên",
                        unit: "mm",
                      },
                      {
                        key: "wheelSize",
                        label: "Kích thước bánh xe",
                        unit: "inch",
                      },
                      { key: "beforeFork", label: "Phuộc trước", unit: "" },
                      { key: "afterFork", label: "Phuộc sau", unit: "" },
                      {
                        key: "maxiumCapacity",
                        label: "Tải trọng tối đa",
                        unit: "kg",
                      },
                      {
                        key: "oilCapacity",
                        label: "Dung tích dầu máy",
                        unit: "lít",
                      },
                      {
                        key: "fuelConsumption",
                        label: "Mức tiêu thụ nhiên liệu",
                        unit: "l/100km",
                      },
                      {
                        key: "cylinderCapacity",
                        label: "Dung tích xi lanh",
                        unit: "cc",
                      },
                      {
                        key: "maxiumMoment",
                        label: "Mômen xoắn tối đa",
                        unit: "Nm",
                      },
                      { key: "compressionRatio", label: "Tỷ số nén", unit: "" },
                      { key: "engieType", label: "Loại động cơ", unit: "" },
                    ].map((spec) => (
                      <div key={spec.key}>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                          {spec.label} {spec.unit && `(${spec.unit})`}
                        </label>
                        <input
                          type="text"
                          value={newProduct[spec.key] || ""}
                          onChange={(e) =>
                            setNewProduct({
                              ...newProduct,
                              [spec.key]: e.target.value,
                            })
                          }
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                          placeholder={`Nhập ${spec.label.toLowerCase()}`}
                        />
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-end space-x-4 p-6 border-t bg-gray-50">
              <button
                onClick={() => setShowAddProductModal(false)}
                className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
              >
                Hủy
              </button>
              <button
                onClick={handleAddProduct}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                Thêm sản phẩm
              </button>
            </div>
          </div>
        </div>
      )}

      {/* View/Edit Product Modal */}
      {showProductModal && selectedProduct && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md mx-4 max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-semibold text-gray-900">
                {modalMode === "view"
                  ? "Chi tiết sản phẩm"
                  : "Chỉnh sửa sản phẩm"}
              </h3>
              <button
                onClick={() => setShowProductModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Tên sản phẩm
                </label>
                <input
                  type="text"
                  value={selectedProduct.name}
                  onChange={(e) =>
                    setSelectedProduct({
                      ...selectedProduct,
                      name: e.target.value,
                    })
                  }
                  disabled={modalMode === "view"}
                  className={`w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 ${
                    modalMode === "view" ? "bg-gray-50" : ""
                  }`}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Mô tả
                </label>
                <textarea
                  value={selectedProduct.description}
                  onChange={(e) =>
                    setSelectedProduct({
                      ...selectedProduct,
                      description: e.target.value,
                    })
                  }
                  disabled={modalMode === "view"}
                  rows={3}
                  className={`w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 ${
                    modalMode === "view" ? "bg-gray-50" : ""
                  }`}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Giá (VND)
                </label>
                <input
                  type="number"
                  value={selectedProduct.price}
                  onChange={(e) =>
                    setSelectedProduct({
                      ...selectedProduct,
                      price: e.target.value,
                    })
                  }
                  disabled={modalMode === "view"}
                  className={`w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 ${
                    modalMode === "view" ? "bg-gray-50" : ""
                  }`}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Thương hiệu
                </label>
                <input
                  type="text"
                  value={selectedProduct.brandName}
                  onChange={(e) =>
                    setSelectedProduct({
                      ...selectedProduct,
                      brandName: e.target.value,
                    })
                  }
                  disabled={modalMode === "view"}
                  className={`w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 ${
                    modalMode === "view" ? "bg-gray-50" : ""
                  }`}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Danh mục
                </label>
                <input
                  type="text"
                  value={selectedProduct.categoryName}
                  onChange={(e) =>
                    setSelectedProduct({
                      ...selectedProduct,
                      categoryName: e.target.value,
                    })
                  }
                  disabled={modalMode === "view"}
                  className={`w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 ${
                    modalMode === "view" ? "bg-gray-50" : ""
                  }`}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Trạng thái
                </label>
                <select
                  value={selectedProduct.status || "ACTIVE"}
                  onChange={(e) =>
                    setSelectedProduct({
                      ...selectedProduct,
                      status: e.target.value,
                    })
                  }
                  disabled={modalMode === "view"}
                  className={`w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 ${
                    modalMode === "view" ? "bg-gray-50" : ""
                  }`}
                >
                  <option value="ACTIVE">Hoạt động</option>
                  <option value="INACTIVE">Không hoạt động</option>
                </select>
              </div>
            </div>

            <div className="flex justify-end space-x-3 mt-6">
              <button
                onClick={() => setShowProductModal(false)}
                className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50"
              >
                {modalMode === "view" ? "Đóng" : "Hủy"}
              </button>
              {modalMode === "view" ? (
                <button
                  onClick={() => setModalMode("edit")}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Chỉnh sửa
                </button>
              ) : (
                <button
                  onClick={handleSaveProduct}
                  className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
                >
                  Lưu thay đổi
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Analytics Tab Component
export const AnalyticsTab = ({
  systemStats,
  orders,
  users,
  formatCurrency,
}) => {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">
          Bảng điều khiển phân tích
        </h2>
        <p className="text-gray-600">Thông tin chi tiết và số liệu hiệu suất</p>
      </div>

      {/* Charts placeholder */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <h3 className="text-lg font-semibold mb-4">Xu hướng doanh thu</h3>
          <div className="h-64 flex items-center justify-center bg-gray-50 rounded">
            <p className="text-gray-500">
              Biểu đồ sẽ được triển khai với thư viện biểu đồ
            </p>
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <h3 className="text-lg font-semibold mb-4">Tăng trưởng người dùng</h3>
          <div className="h-64 flex items-center justify-center bg-gray-50 rounded">
            <p className="text-gray-500">
              Biểu đồ sẽ được triển khai với thư viện biểu đồ
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

// Settings Tab Component
export const SettingsTab = () => {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Cài đặt hệ thống</h2>
        <p className="text-gray-600">Cấu hình tùy chọn và cài đặt hệ thống</p>
      </div>

      <div className="bg-white p-6 rounded-lg shadow-sm border">
        <h3 className="text-lg font-semibold mb-4">Cài đặt chung</h3>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Tên trang web
            </label>
            <input
              type="text"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
              defaultValue="Cửa hàng xe máy"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Email quản trị
            </label>
            <input
              type="email"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
              defaultValue="admin@cuahangxemay.com"
            />
          </div>
          <div className="pt-4">
            <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
              Lưu cài đặt
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
