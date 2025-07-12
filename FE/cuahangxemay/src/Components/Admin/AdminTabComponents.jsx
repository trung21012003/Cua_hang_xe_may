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
  Camera,
} from "lucide-react";
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  Area,
  AreaChart
} from 'recharts';

// Users Tab Component - Đã có đầy đủ chức năng
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
  // Toast notification function
  const showNotification = (message, type = "info") => {
    // Create toast notification
    const toast = document.createElement('div');
    toast.className = `fixed top-4 right-4 z-50 px-6 py-3 rounded-lg shadow-lg text-white font-medium transition-all duration-300 transform translate-x-full ${
      type === 'success' ? 'bg-green-500' : 
      type === 'error' ? 'bg-red-500' : 
      type === 'warning' ? 'bg-yellow-500' : 'bg-blue-500'
    }`;
    toast.textContent = message;
    
    document.body.appendChild(toast);
    
    // Animate in
    setTimeout(() => {
      toast.classList.remove('translate-x-full');
    }, 100);
    
    // Remove after 3 seconds
    setTimeout(() => {
      toast.classList.add('translate-x-full');
      setTimeout(() => {
        document.body.removeChild(toast);
      }, 300);
    }, 3000);
  };

  // Export function with Vietnamese support
  const handleExportUsers = () => {
    try {
      if (!filteredUsers || filteredUsers.length === 0) {
        showNotification("Không có dữ liệu để xuất", "warning");
        return;
      }

      // Get role display name
      const getRoleDisplayName = (roleCode) => {
        switch (roleCode) {
          case "0": return "Quản lý";
          case "2": return "Nhân viên";
          case "1": return "Khách hàng";
          default: return "Không xác định";
        }
      };

      // Get status display name
      const getStatusDisplayName = (status) => {
        switch (status) {
          case "ACTIVE": return "Hoạt động";
          case "INACTIVE": return "Ngừng hoạt động";
          case "PENDING": return "Chờ duyệt";
          default: return "Không xác định";
        }
      };

      // Format date
      const formatExportDate = (dateStr) => {
        try {
          if (!dateStr) return "Chưa có";
          const date = new Date(dateStr);
          if (isNaN(date.getTime())) return "Ngày không hợp lệ";
          return date.toLocaleDateString('vi-VN');
        } catch (error) {
          return "Ngày không hợp lệ";
        }
      };

      // Prepare data for export
      const exportData = filteredUsers.map(user => ({
        'Tên đăng nhập': user.username || '',
        'Họ và tên': user.name || '',
        'Email': user.email || '',
        'Số điện thoại': user.phone || '',
        'Địa chỉ': user.address || '',
        'Vai trò': getRoleDisplayName(user.role),
        'Trạng thái': getStatusDisplayName(user.status),
        'Ngày tạo': formatExportDate(user.created || user.createdAt)
      }));

      // Convert to CSV with UTF-8 BOM for Vietnamese support
      const headers = Object.keys(exportData[0]);
      const csvContent = [
        headers.join(','),
        ...exportData.map(row => 
          headers.map(header => {
            const value = row[header] || '';
            // Escape quotes and wrap in quotes if contains comma
            return value.includes(',') || value.includes('"') ? 
              `"${value.replace(/"/g, '""')}"` : value;
          }).join(',')
        )
      ].join('\n');

      // Add UTF-8 BOM for proper Vietnamese display
      const BOM = '\uFEFF';
      const blob = new Blob([BOM + csvContent], { 
        type: 'text/csv;charset=utf-8;' 
      });

      // Create download link
      const link = document.createElement('a');
      const url = URL.createObjectURL(blob);
      link.setAttribute('href', url);
      link.setAttribute('download', `danh-sach-nguoi-dung-${new Date().toISOString().split('T')[0]}.csv`);
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      showNotification(`Đã xuất ${exportData.length} người dùng thành công!`, "success");
    } catch (error) {
      console.error('Export error:', error);
      showNotification("Lỗi khi xuất dữ liệu: " + error.message, "error");
    }
  };
  const [selectedUsers, setSelectedUsers] = useState([]);
  const [showUserModal, setShowUserModal] = useState(false);
  const [showAddUserModal, setShowAddUserModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [modalMode, setModalMode] = useState("view");
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
      
      // Toast notification thay vì alert
      showNotification("Thêm người dùng thành công!", "success");
      
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
      showNotification(
        "Lỗi khi thêm người dùng: " +
          (error.response?.data?.message || error.message),
        "error"
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
      showNotification("Cập nhật người dùng thành công!", "success");
      setShowUserModal(false);
      fetchUsers();
    } catch (error) {
      console.error("Error updating user:", error);
      showNotification(
        "Lỗi khi cập nhật người dùng: " +
          (error.response?.data?.message || error.message),
        "error"
      );
    }
  };

  return (
    <div className="space-y-6">
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
          <button 
            onClick={handleExportUsers}
            className="flex items-center px-4 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50"
          >
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
              <option value="0">Quản lý</option>
              <option value="2">Nhân viên</option>
              <option value="1">Khách hàng</option>
            </select>
            <select 
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">Tất cả trạng thái</option>
              <option value="ACTIVE">Hoạt động</option>
              <option value="INACTIVE">Ngừng hoạt động</option>
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
                  Người dùng
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Email
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
                    <div className="flex items-center">
                      <div className="w-10 h-10 bg-gray-100 rounded-full flex items-center justify-center">
                        <span className="text-gray-600 font-medium">
                          {user.username?.[0]?.toUpperCase() || "U"}
                        </span>
                      </div>
                      <div className="ml-3">
                        <div className="text-sm font-medium text-gray-900">
                          {user.username}
                        </div>
                        <div className="text-sm text-gray-500">
                          {user.phone || "Chưa có SĐT"}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900">{user.email}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <select
                      value={user.role}
                      onChange={(e) => updateUserRole && updateUserRole(user.id, e.target.value)}
                      className="text-sm border rounded px-2 py-1 focus:ring-blue-500 focus:border-blue-500"
                    >
                      <option value="0">Quản lý</option>
                      <option value="2">Nhân viên</option>
                      <option value="1">Khách hàng</option>
                    </select>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <select
                      value={user.status}
                      onChange={(e) => updateUserStatus && updateUserStatus(user.id, e.target.value)}
                      className={`text-sm border rounded px-2 py-1 focus:ring-blue-500 focus:border-blue-500 ${
                        user.status === "ACTIVE"
                          ? "bg-green-100 text-green-800"
                          : "bg-red-100 text-red-800"
                      }`}
                    >
                      <option value="ACTIVE">Hoạt động</option>
                      <option value="INACTIVE">Ngừng hoạt động</option>
                    </select>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {user.created || user.createdAt ? 
                      (() => {
                        try {
                          const dateStr = user.created || user.createdAt;
                          if (!dateStr) return "Chưa có";
                          
                          const date = new Date(dateStr);
                          if (isNaN(date.getTime())) return "Ngày không hợp lệ";
                          
                          return formatDate ? formatDate(dateStr) : date.toLocaleDateString('vi-VN');
                        } catch (error) {
                          return "Ngày không hợp lệ";
                        }
                      })()
                      : "Chưa có"
                    }
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <div className="flex space-x-2">
                      <button
                        onClick={() => handleViewUser(user)}
                        className="text-blue-600 hover:text-blue-900"
                      >
                        <Eye className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => handleEditUser(user)}
                        className="text-green-600 hover:text-green-900"
                      >
                        <Edit className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => deleteUser && deleteUser(user.id)}
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
      </div>

      {/* Add User Modal */}
      {showAddUserModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg w-full max-w-2xl max-h-[90vh] overflow-hidden">
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
            
            <div className="overflow-y-auto max-h-[70vh] p-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Tên đăng nhập *
                </label>
                <input
                  type="text"
                  value={newUser.username}
                    onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Nhập tên đăng nhập"
                />
              </div>
              <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Email *
                </label>
                <input
                  type="email"
                  value={newUser.email}
                    onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Nhập email"
                />
              </div>
              <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Mật khẩu *
                </label>
                <input
                  type="password"
                  value={newUser.password}
                    onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Nhập mật khẩu"
                />
              </div>
              <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Họ và tên *
                  </label>
                  <input
                    type="text"
                    value={newUser.name}
                    onChange={(e) => setNewUser({ ...newUser, name: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Nhập họ và tên"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Số điện thoại *
                  </label>
                  <input
                    type="tel"
                    value={newUser.phone}
                    onChange={(e) => setNewUser({ ...newUser, phone: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Nhập số điện thoại"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Địa chỉ *
                  </label>
                  <input
                    type="text"
                    value={newUser.address}
                    onChange={(e) => setNewUser({ ...newUser, address: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Nhập địa chỉ"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                  Vai trò
                </label>
                <select
                  value={newUser.role}
                    onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                >
                    <option value="0">Quản lý</option>
                    <option value="2">Nhân viên</option>
                    <option value="1">Khách hàng</option>
                </select>
              </div>
              <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                  Trạng thái
                </label>
                <select
                  value={newUser.status}
                    onChange={(e) => setNewUser({ ...newUser, status: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                >
                  <option value="ACTIVE">Hoạt động</option>
                    <option value="INACTIVE">Ngừng hoạt động</option>
                </select>
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
          <div className="bg-white rounded-lg w-full max-w-2xl max-h-[90vh] overflow-hidden">
            <div className="flex justify-between items-center p-6 border-b">
              <h3 className="text-lg font-semibold text-gray-900">
                {modalMode === "view" ? "Thông tin người dùng" : "Chỉnh sửa người dùng"}
              </h3>
              <button
                onClick={() => setShowUserModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            
            <div className="overflow-y-auto max-h-[70vh] p-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Tên đăng nhập
                </label>
                <input
                  type="text"
                  value={selectedUser.username}
                    onChange={(e) => setSelectedUser({ ...selectedUser, username: e.target.value })}
                    disabled={modalMode === "view"}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100"
                />
              </div>
              <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                  Email
                </label>
                <input
                  type="email"
                  value={selectedUser.email}
                    onChange={(e) => setSelectedUser({ ...selectedUser, email: e.target.value })}
                    disabled={modalMode === "view"}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100"
                />
              </div>
              <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Họ và tên
                  </label>
                  <input
                    type="text"
                    value={selectedUser.name || ""}
                    onChange={(e) => setSelectedUser({ ...selectedUser, name: e.target.value })}
                    disabled={modalMode === "view"}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Số điện thoại
                  </label>
                  <input
                    type="tel"
                    value={selectedUser.phone || ""}
                    onChange={(e) => setSelectedUser({ ...selectedUser, phone: e.target.value })}
                    disabled={modalMode === "view"}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100"
                  />
                </div>
                <div className="md:col-span-2">
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Địa chỉ
                  </label>
                  <input
                    type="text"
                    value={selectedUser.address || ""}
                    onChange={(e) => setSelectedUser({ ...selectedUser, address: e.target.value })}
                    disabled={modalMode === "view"}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                  Vai trò
                </label>
                <select
                  value={selectedUser.role}
                    onChange={(e) => setSelectedUser({ ...selectedUser, role: e.target.value })}
                    disabled={modalMode === "view"}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100"
                >
                    <option value="0">Quản lý</option>
                    <option value="2">Nhân viên</option>
                    <option value="1">Khách hàng</option>
                </select>
              </div>
              <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                  Trạng thái
                </label>
                <select
                  value={selectedUser.status}
                    onChange={(e) => setSelectedUser({ ...selectedUser, status: e.target.value })}
                    disabled={modalMode === "view"}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100"
                >
                  <option value="ACTIVE">Hoạt động</option>
                    <option value="INACTIVE">Ngừng hoạt động</option>
                </select>
              </div>
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
                {modalMode === "edit" && (
                <button
                    onClick={handleSaveUser}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                    Lưu thay đổi
                </button>
                )}
                {modalMode === "view" && (
                <button
                    onClick={() => setModalMode("edit")}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                    Chỉnh sửa
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

// Orders Tab Component - Quản lý đơn hàng
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
  const [searchQuery, setSearchQuery] = useState("");
  const [dateFilter, setDateFilter] = useState("all");
  const [sortBy, setSortBy] = useState("orderDate");
  const [sortOrder, setSortOrder] = useState("desc");

  // Toast notification function
  const showNotification = (message, type = "info") => {
    const toast = document.createElement('div');
    toast.className = `fixed top-4 right-4 z-50 px-6 py-3 rounded-lg shadow-lg text-white font-medium transition-all duration-300 transform translate-x-full ${
      type === 'success' ? 'bg-green-500' : 
      type === 'error' ? 'bg-red-500' : 
      type === 'warning' ? 'bg-yellow-500' : 'bg-blue-500'
    }`;
    toast.textContent = message;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
      toast.classList.remove('translate-x-full');
    }, 100);
    
    setTimeout(() => {
      toast.classList.add('translate-x-full');
      setTimeout(() => {
        document.body.removeChild(toast);
      }, 300);
    }, 3000);
  };

  // Export function for orders
  const handleExportOrders = () => {
    try {
      if (!filteredOrders || filteredOrders.length === 0) {
        showNotification("Không có dữ liệu để xuất", "warning");
        return;
      }

      const getStatusDisplayName = (status) => {
        const statusMap = {
          'PENDING': 'Chờ xử lý',
          'CONFIRMED': 'Đã xác nhận', 
          'PROCESSING': 'Đang xử lý',
          'SHIPPED': 'Đã gửi',
          'DELIVERED': 'Đã giao',
          'CANCELLED': 'Đã hủy'
        };
        return statusMap[status] || status;
      };

      const formatExportDate = (dateStr) => {
        try {
          if (!dateStr) return "Chưa có";
          const date = new Date(dateStr);
          if (isNaN(date.getTime())) return "Ngày không hợp lệ";
          return date.toLocaleDateString('vi-VN');
        } catch (error) {
          return "Ngày không hợp lệ";
        }
      };

      const exportData = filteredOrders.map(order => ({
        'Mã đơn hàng': `#${order.id}`,
        'Khách hàng': order.user?.username || 'Không rõ',
        'Email': order.user?.email || '',
        'Số điện thoại': order.shippingPhone || '',
        'Địa chỉ giao hàng': order.shippingAddress || '',
        'Tổng tiền': order.totalAmount || 0,
        'Phương thức thanh toán': order.paymentMethod || '',
        'Trạng thái': getStatusDisplayName(order.status),
        'Ngày đặt': formatExportDate(order.orderDate),
        'Ghi chú': order.notes || ''
      }));

      const headers = Object.keys(exportData[0]);
      const csvContent = [
        headers.join(','),
        ...exportData.map(row => 
          headers.map(header => {
            const value = String(row[header] || '');
            return value.includes(',') || value.includes('"') ? 
              `"${value.replace(/"/g, '""')}"` : value;
          }).join(',')
        )
      ].join('\n');

      const BOM = '\uFEFF';
      const blob = new Blob([BOM + csvContent], { 
        type: 'text/csv;charset=utf-8;' 
      });

      const link = document.createElement('a');
      const url = URL.createObjectURL(blob);
      link.setAttribute('href', url);
      link.setAttribute('download', `danh-sach-don-hang-${new Date().toISOString().split('T')[0]}.csv`);
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      showNotification(`Đã xuất ${exportData.length} đơn hàng thành công!`, "success");
    } catch (error) {
      console.error('Export error:', error);
      showNotification("Lỗi khi xuất dữ liệu: " + error.message, "error");
    }
  };

  // Filter orders by date range
  const filterOrdersByDate = (orders, dateFilter) => {
    if (!orders || dateFilter === "all") return orders;
    
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    
    return orders.filter(order => {
      if (!order.orderDate) return false;
      
      try {
        const orderDate = new Date(order.orderDate);
        if (isNaN(orderDate.getTime())) return false;
        
        switch (dateFilter) {
          case "today":
            return orderDate >= today;
          case "week":
            const weekAgo = new Date(today);
            weekAgo.setDate(weekAgo.getDate() - 7);
            return orderDate >= weekAgo;
          case "month":
            const monthAgo = new Date(today);
            monthAgo.setMonth(monthAgo.getMonth() - 1);
            return orderDate >= monthAgo;
          case "quarter":
            const quarterAgo = new Date(today);
            quarterAgo.setMonth(quarterAgo.getMonth() - 3);
            return orderDate >= quarterAgo;
          default:
            return true;
        }
      } catch (error) {
        return false;
      }
    });
  };

  const statusColors = {
    PENDING: "bg-yellow-100 text-yellow-800",
    CONFIRMED: "bg-blue-100 text-blue-800",
    PROCESSING: "bg-purple-100 text-purple-800",
    SHIPPED: "bg-indigo-100 text-indigo-800",
    DELIVERED: "bg-green-100 text-green-800",
    CANCELLED: "bg-red-100 text-red-800",
  };

  // Enhanced filtering with search, date, and sorting
  const filteredOrders = (() => {
    if (!Array.isArray(orders)) return [];
    
    let filtered = orders;
    
    // Filter by status
    if (orderFilter !== "all") {
      filtered = filtered.filter(order => order.status === orderFilter);
    }
    
    // Filter by search query
    if (searchQuery.trim()) {
      filtered = filtered.filter(order => 
        order.id?.toString().includes(searchQuery) ||
        order.user?.username?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        order.user?.email?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        order.shippingPhone?.includes(searchQuery)
      );
    }
    
    // Filter by date range
    filtered = filterOrdersByDate(filtered, dateFilter);
    
    // Sort orders
    filtered.sort((a, b) => {
      let aValue = a[sortBy];
      let bValue = b[sortBy];
      
      if (sortBy === 'orderDate') {
        aValue = new Date(aValue || 0);
        bValue = new Date(bValue || 0);
      } else if (sortBy === 'totalAmount') {
        aValue = Number(aValue || 0);
        bValue = Number(bValue || 0);
      } else if (sortBy === 'user') {
        aValue = a.user?.username || '';
        bValue = b.user?.username || '';
      }
      
      if (sortOrder === 'desc') {
        return bValue > aValue ? 1 : -1;
      } else {
        return aValue > bValue ? 1 : -1;
      }
    });
    
    return filtered;
  })();

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Quản lý đơn hàng</h2>
          <p className="text-gray-600">
            Theo dõi và quản lý đơn hàng khách hàng
          </p>
        </div>
        <div className="flex space-x-3">
          <button 
            onClick={handleExportOrders}
            className="flex items-center px-4 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50"
          >
            <Download className="h-4 w-4 mr-2" />
            Xuất dữ liệu
          </button>
          <button className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
            <RefreshCw className="h-4 w-4 mr-2" />
            Làm mới
          </button>
        </div>
      </div>

      {/* Enhanced Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Tổng đơn hàng</p>
              <p className="text-2xl font-bold text-gray-900">
                {filteredOrders?.length || 0}
              </p>
              <p className="text-xs text-gray-500 mt-1">
                Từ {orders?.length || 0} đơn tổng
              </p>
            </div>
            <div className="p-2 bg-blue-100 rounded">
              <ShoppingCart className="h-6 w-6 text-blue-600" />
            </div>
            </div>
          </div>
        
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Chờ xử lý</p>
              <p className="text-2xl font-bold text-yellow-600">
                {filteredOrders?.filter((o) => o.status === "PENDING").length || 0}
              </p>
              <p className="text-xs text-gray-500 mt-1">
                Cần xử lý ngay
              </p>
            </div>
            <div className="p-2 bg-yellow-100 rounded">
              <AlertTriangle className="h-6 w-6 text-yellow-600" />
          </div>
        </div>
            </div>
        
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Đã giao</p>
              <p className="text-2xl font-bold text-green-600">
                {filteredOrders?.filter((o) => o.status === "DELIVERED").length || 0}
              </p>
              <p className="text-xs text-gray-500 mt-1">
                Hoàn thành thành công
              </p>
            </div>
            <div className="p-2 bg-green-100 rounded">
              <CheckCircle className="h-6 w-6 text-green-600" />
          </div>
        </div>
        </div>
        
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Doanh thu</p>
              <p className="text-2xl font-bold text-purple-600">
                {formatCurrency ? formatCurrency(
                  filteredOrders?.reduce(
                    (sum, order) => sum + (order.totalAmount || 0),
                    0
                  ) || 0
                ) : "0 VND"}
              </p>
              <p className="text-xs text-gray-500 mt-1">
                Từ {filteredOrders?.length || 0} đơn
              </p>
            </div>
            <div className="p-2 bg-purple-100 rounded">
              <DollarSign className="h-6 w-6 text-purple-600" />
            </div>
            </div>
          </div>
      </div>

      {/* Additional Statistics Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white p-4 rounded-lg shadow-sm border">
          <h4 className="text-sm font-medium text-gray-900 mb-3">Tỷ lệ trạng thái</h4>
          <div className="space-y-2">
            {[
              { status: 'PENDING', label: 'Chờ xử lý', color: 'yellow' },
              { status: 'PROCESSING', label: 'Đang xử lý', color: 'blue' },
              { status: 'DELIVERED', label: 'Đã giao', color: 'green' },
              { status: 'CANCELLED', label: 'Đã hủy', color: 'red' }
            ].map(({ status, label, color }) => {
              const count = filteredOrders?.filter(o => o.status === status).length || 0;
              const percentage = filteredOrders?.length ? Math.round((count / filteredOrders.length) * 100) : 0;
              return (
                <div key={status} className="flex items-center justify-between text-sm">
                  <span className="text-gray-600">{label}</span>
                  <div className="flex items-center space-x-2">
                    <div className={`w-12 h-2 bg-gray-200 rounded-full overflow-hidden`}>
                      <div 
                        className={`h-full bg-${color}-500`}
                        style={{ width: `${percentage}%` }}
                      ></div>
                    </div>
                    <span className="text-gray-900 font-medium w-8">{count}</span>
                  </div>
                </div>
              );
            })}
        </div>
      </div>

      <div className="bg-white p-4 rounded-lg shadow-sm border">
          <h4 className="text-sm font-medium text-gray-900 mb-3">Giá trị đơn hàng</h4>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-600">Trung bình:</span>
              <span className="font-medium">
                {formatCurrency ? formatCurrency(
                  filteredOrders?.length ? 
                    filteredOrders.reduce((sum, o) => sum + (o.totalAmount || 0), 0) / filteredOrders.length 
                    : 0
                ) : "0 VND"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Cao nhất:</span>
              <span className="font-medium text-green-600">
                {formatCurrency ? formatCurrency(
                  Math.max(...(filteredOrders?.map(o => o.totalAmount || 0) || [0]))
                ) : "0 VND"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Thấp nhất:</span>
              <span className="font-medium text-red-600">
                {formatCurrency ? formatCurrency(
                  Math.min(...(filteredOrders?.map(o => o.totalAmount || 0).filter(a => a > 0) || [0]))
                ) : "0 VND"}
              </span>
            </div>
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg shadow-sm border">
          <h4 className="text-sm font-medium text-gray-900 mb-3">Thời gian xử lý</h4>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-600">Hôm nay:</span>
              <span className="font-medium">
                {filterOrdersByDate(orders || [], 'today').length} đơn
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Tuần này:</span>
              <span className="font-medium">
                {filterOrdersByDate(orders || [], 'week').length} đơn
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Tháng này:</span>
              <span className="font-medium">
                {filterOrdersByDate(orders || [], 'month').length} đơn
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Enhanced Filters */}
      <div className="bg-white p-4 rounded-lg shadow-sm border">
        <div className="flex flex-col lg:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
            <input
              type="text"
              placeholder="Tìm kiếm theo ID, khách hàng, email, SĐT..."
              className="pl-10 pr-4 py-2 w-full border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
          <div className="flex flex-wrap gap-2">
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
            <select 
              value={dateFilter}
              onChange={(e) => setDateFilter(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">Tất cả thời gian</option>
              <option value="today">Hôm nay</option>
              <option value="week">7 ngày qua</option>
              <option value="month">30 ngày qua</option>
              <option value="quarter">3 tháng qua</option>
            </select>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="orderDate">Sắp xếp theo ngày</option>
              <option value="totalAmount">Sắp xếp theo tiền</option>
              <option value="user">Sắp xếp theo khách hàng</option>
              <option value="status">Sắp xếp theo trạng thái</option>
            </select>
            <button
              onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
              className="px-3 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 focus:ring-blue-500 focus:border-blue-500"
              title={sortOrder === 'asc' ? 'Tăng dần' : 'Giảm dần'}
            >
              {sortOrder === 'asc' ? '↑' : '↓'}
            </button>
          </div>
        </div>
        
        {/* Filter Summary */}
        <div className="mt-3 flex flex-wrap gap-2 text-sm text-gray-600">
          <span>Hiển thị {filteredOrders.length} / {orders?.length || 0} đơn hàng</span>
          {searchQuery && <span className="bg-blue-100 text-blue-800 px-2 py-1 rounded">Tìm kiếm: "{searchQuery}"</span>}
          {orderFilter !== "all" && <span className="bg-green-100 text-green-800 px-2 py-1 rounded">Trạng thái: {orderFilter}</span>}
          {dateFilter !== "all" && <span className="bg-purple-100 text-purple-800 px-2 py-1 rounded">Thời gian: {dateFilter}</span>}
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
              {filteredOrders.map((order) => (
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
                      {formatCurrency ? formatCurrency(order.totalAmount) : `${order.totalAmount} VND`}
                    </div>
                    <div className="text-sm text-gray-500">
                      {order.paymentMethod || "Chưa rõ"}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <select
                      value={order.status}
                      onChange={(e) =>
                        updateOrderStatus && updateOrderStatus(order.id, e.target.value)
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
                    {order.orderDate ? 
                      (() => {
                        try {
                          const dateStr = order.orderDate;
                          if (!dateStr) return "Chưa có";
                          
                          const date = new Date(dateStr);
                          if (isNaN(date.getTime())) return "Ngày không hợp lệ";
                          
                          return formatDate ? formatDate(dateStr) : date.toLocaleDateString('vi-VN');
                        } catch (error) {
                          return "Ngày không hợp lệ";
                        }
                      })()
                      : "Chưa có"
                    }
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <div className="flex space-x-2">
                      <button
                        onClick={() => {
                          setSelectedOrder(order);
                          setShowOrderModal(true);
                        }}
                        className="text-blue-600 hover:text-blue-900"
                        title="Xem chi tiết"
                      >
                        <Eye className="h-4 w-4" />
                      </button>
                      {order.status === 'PENDING' && (
                        <button
                          onClick={() => {
                            updateOrderStatus && updateOrderStatus(order.id, 'CONFIRMED');
                            showNotification("Đã xác nhận đơn hàng #" + order.id, "success");
                          }}
                          className="text-green-600 hover:text-green-900"
                          title="Xác nhận đơn hàng"
                        >
                          <CheckCircle className="h-4 w-4" />
                      </button>
                      )}
                      {(order.status === 'CONFIRMED' || order.status === 'PROCESSING') && (
                        <button
                          onClick={() => {
                            const nextStatus = order.status === 'CONFIRMED' ? 'PROCESSING' : 'SHIPPED';
                            updateOrderStatus && updateOrderStatus(order.id, nextStatus);
                            showNotification(`Đã cập nhật trạng thái đơn hàng #${order.id}`, "success");
                          }}
                          className="text-purple-600 hover:text-purple-900"
                          title={order.status === 'CONFIRMED' ? 'Chuyển sang xử lý' : 'Chuyển sang đã gửi'}
                        >
                          <Zap className="h-4 w-4" />
                        </button>
                      )}
                      {order.status !== 'CANCELLED' && order.status !== 'DELIVERED' && (
                        <button
                          onClick={() => {
                            if (window.confirm(`Bạn có chắc muốn hủy đơn hàng #${order.id}?`)) {
                              updateOrderStatus && updateOrderStatus(order.id, 'CANCELLED');
                              showNotification("Đã hủy đơn hàng #" + order.id, "warning");
                            }
                          }}
                          className="text-red-600 hover:text-red-900"
                          title="Hủy đơn hàng"
                        >
                          <X className="h-4 w-4" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Order Detail Modal */}
      {showOrderModal && selectedOrder && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg w-full max-w-4xl max-h-[90vh] overflow-hidden">
            <div className="flex justify-between items-center p-6 border-b">
              <h3 className="text-lg font-semibold text-gray-900">
                Chi tiết đơn hàng #{selectedOrder.id}
              </h3>
              <button
                onClick={() => setShowOrderModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="overflow-y-auto max-h-[70vh] p-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-3">Thông tin khách hàng</h4>
                  <div className="space-y-2">
                    <p><span className="font-medium">Tên:</span> {selectedOrder.user?.username || "N/A"}</p>
                    <p><span className="font-medium">Email:</span> {selectedOrder.user?.email || "N/A"}</p>
                    <p><span className="font-medium">SĐT:</span> {selectedOrder.shippingPhone || "N/A"}</p>
                    <p><span className="font-medium">Địa chỉ:</span> {selectedOrder.shippingAddress || "N/A"}</p>
                  </div>
                </div>

                                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-3">Thông tin đơn hàng</h4>
                    <div className="space-y-2">
                      <p><span className="font-medium">Ngày đặt:</span> {
                        selectedOrder.orderDate ? 
                          (() => {
                            try {
                              const date = new Date(selectedOrder.orderDate);
                              return isNaN(date.getTime()) ? "Ngày không hợp lệ" : 
                                (formatDate ? formatDate(selectedOrder.orderDate) : date.toLocaleDateString('vi-VN'));
                            } catch (error) {
                              return "Ngày không hợp lệ";
                            }
                          })() : "Chưa có"
                      }</p>
                      <p><span className="font-medium">Phương thức thanh toán:</span> {selectedOrder.paymentMethod || "N/A"}</p>
                      <p><span className="font-medium">Tổng tiền:</span> 
                        <span className="text-lg font-bold text-green-600 ml-2">
                          {formatCurrency ? formatCurrency(selectedOrder.totalAmount) : `${selectedOrder.totalAmount} VND`}
                        </span>
                      </p>
                      <p><span className="font-medium">Trạng thái:</span> 
                        <span className={`ml-2 px-2 py-1 rounded-full text-xs font-medium ${
                          statusColors[selectedOrder.status] || "bg-gray-100 text-gray-800"
                        }`}>
                          {selectedOrder.status === "PENDING" ? "Chờ xử lý" :
                           selectedOrder.status === "CONFIRMED" ? "Đã xác nhận" :
                           selectedOrder.status === "PROCESSING" ? "Đang xử lý" :
                           selectedOrder.status === "SHIPPED" ? "Đã gửi" :
                           selectedOrder.status === "DELIVERED" ? "Đã giao" :
                           selectedOrder.status === "CANCELLED" ? "Đã hủy" :
                           selectedOrder.status}
                        </span>
                      </p>
                      <p><span className="font-medium">Ghi chú:</span> {selectedOrder.notes || "Không có"}</p>
                    </div>
                  </div>
              </div>

              <div className="mt-6">
                <h4 className="text-sm font-medium text-gray-900 mb-3">Chi tiết sản phẩm</h4>
                <div className="bg-gray-50 rounded-lg p-4">
                  {selectedOrder.orderDetails && selectedOrder.orderDetails.length > 0 ? (
                    selectedOrder.orderDetails.map((detail, index) => (
                      <div key={index} className="flex justify-between items-center py-2 border-b border-gray-200 last:border-b-0">
                        <div>
                          <p className="font-medium">{detail.product?.name || "Sản phẩm"}</p>
                          <p className="text-sm text-gray-600">Số lượng: {detail.quantity}</p>
                        </div>
                        <p className="font-medium">{formatCurrency ? formatCurrency(detail.price * detail.quantity) : `${detail.price * detail.quantity} VND`}</p>
                      </div>
                    ))
                  ) : (
                    <p className="text-gray-500">Không có thông tin chi tiết sản phẩm</p>
                  )}
                </div>
              </div>
            </div>

            <div className="border-t p-6">
              <div className="flex justify-end space-x-3">
                <button
                  onClick={() => setShowOrderModal(false)}
                  className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50"
                >
                  Đóng
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Products Tab Component - Quản lý sản phẩm  
export const ProductsTab = ({
  products,
  formatCurrency,
  formatDate,
  fetchProducts,
  addProduct,
  updateProduct,
  deleteProduct,
}) => {
  const [productFilter, setProductFilter] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [brandFilter, setBrandFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [showAddProductModal, setShowAddProductModal] = useState(false);
  const [showProductModal, setShowProductModal] = useState(false);
  const [selectedProduct, setSelectedProduct] = useState(null);
  const [modalMode, setModalMode] = useState("view");
  const [newProduct, setNewProduct] = useState({
    name: "",
    description: "",
    price: "",
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
    status: "ACTIVE",
    versionColors: []
  });
  const [previewImage, setPreviewImage] = useState(null);
  const [previewColorImages, setPreviewColorImages] = useState({});

  // Default placeholder image
  const defaultImage = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 100 100'%3E%3Crect width='100' height='100' fill='%23f3f4f6'/%3E%3Ctext x='50' y='50' font-family='Arial' font-size='12' fill='%239ca3af' text-anchor='middle' dominant-baseline='middle'%3ENo Image%3C/text%3E%3C/svg%3E";

  // Get unique categories and brands for filters
  const categories = [...new Set(products?.map((p) => p.motolineName).filter(Boolean))];
  const brands = [...new Set(products?.map((p) => p.brandName).filter(Boolean))];

  // Filter products based on search and filters
  const filteredProducts = Array.isArray(products)
    ? products.filter((product) => {
        const matchesSearch =
          product.name?.toLowerCase().includes(productFilter.toLowerCase()) ||
                         product.description?.toLowerCase().includes(productFilter.toLowerCase());
        const matchesCategory =
          categoryFilter === "all" || product.motolineName === categoryFilter;
        const matchesBrand =
          brandFilter === "all" || product.brandName === brandFilter;
        const matchesStatus =
          statusFilter === "all" || product.status === statusFilter;
    
    return matchesSearch && matchesCategory && matchesBrand && matchesStatus;
      })
    : [];

  // Export products to CSV
  const handleExportProducts = () => {
    try {
      if (!filteredProducts || filteredProducts.length === 0) {
        alert("Không có dữ liệu để xuất");
        return;
      }

      // Prepare data for export
      const exportData = filteredProducts.map(product => ({
        'Tên sản phẩm': product.name || '',
        'Mô tả': product.description || '',
        'Giá': formatCurrency ? formatCurrency(product.price) : `${product.price} VND`,
        'Hãng': product.brandName || '',
        'Dòng': product.motolineName || '',
        'Trạng thái': product.status === 'ACTIVE' ? 'Hoạt động' : 'Ngừng hoạt động',
        'Số lượng': product.totalStock || 0,
        'Trọng lượng': product.weight || '',
        'Kích thước': product.size || '',
        'Dung tích': product.capacity || ''
      }));

      // Convert to CSV
      const headers = Object.keys(exportData[0]);
      const csvContent = [
        headers.join(','),
        ...exportData.map(row => 
          headers.map(header => {
            const value = row[header] || '';
            return value.includes(',') || value.includes('"') ? 
              `"${value.replace(/"/g, '""')}"` : value;
          }).join(',')
        )
      ].join('\n');

      // Add UTF-8 BOM for proper Vietnamese display
      const BOM = '\uFEFF';
      const blob = new Blob([BOM + csvContent], { 
        type: 'text/csv;charset=utf-8;' 
      });

      // Create download link
      const link = document.createElement('a');
      const url = URL.createObjectURL(blob);
      link.setAttribute('href', url);
      link.setAttribute('download', `danh-sach-san-pham-${new Date().toISOString().split('T')[0]}.csv`);
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      alert(`Đã xuất ${exportData.length} sản phẩm thành công!`);
    } catch (error) {
      console.error('Export error:', error);
      alert("Lỗi khi xuất dữ liệu: " + error.message);
    }
  };

  const handleAddProduct = async () => {
    try {
      const token = localStorage.getItem("jwtToken");
      if (!token) {
        alert("Vui lòng đăng nhập lại để tiếp tục");
        return;
      }

      const result = await addProduct(newProduct);
      if (result) {
      setShowAddProductModal(false);
      setNewProduct({
          name: "",
          description: "",
          price: "",
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
          status: "ACTIVE",
          versionColors: []
        });
        setPreviewImage(null);
        setPreviewColorImages({});
      }
    } catch (error) {
      console.error("Error adding product:", error);
      alert(error.message || "Có lỗi xảy ra khi thêm sản phẩm");
    }
  };

  const handleSaveProduct = async () => {
    try {
      await updateProduct(selectedProduct.id, selectedProduct);
      setShowProductModal(false);
    } catch (error) {
      console.error("Error updating product:", error);
    }
  };

  const handleDeleteProduct = async (productId) => {
    if (window.confirm("Bạn có chắc chắn muốn xóa sản phẩm này? Hành động này không thể hoàn tác.")) {
      try {
        await deleteProduct(productId);
        alert("Xóa sản phẩm thành công!");
    } catch (error) {
        console.error("Error deleting product:", error);
        alert("Lỗi khi xóa sản phẩm: " + error.message);
      }
    }
  };

  const handleImageUpload = (e, type, versionIndex = null, colorIndex = null) => {
    const file = e.target.files[0];
    if (file) {
      if (type === 'product') {
        setNewProduct({ ...newProduct, avatar: file });
        setPreviewImage(URL.createObjectURL(file));
      } else if (type === 'color' && versionIndex !== null && colorIndex !== null) {
        const newVersions = [...newProduct.versionColors];
        newVersions[versionIndex].colors[colorIndex].photo = file;
        setNewProduct({ ...newProduct, versionColors: newVersions });
        setPreviewColorImages({
          ...previewColorImages,
          [`${versionIndex}-${colorIndex}`]: URL.createObjectURL(file)
        });
      }
    }
  };

  const handleProductImageUpload = (e, type, versionIndex = null, colorIndex = null) => {
    const file = e.target.files[0];
    if (file) {
      if (type === 'product') {
        setSelectedProduct({ ...selectedProduct, avatar: file });
        setPreviewImage(URL.createObjectURL(file));
      } else if (type === 'color' && versionIndex !== null && colorIndex !== null) {
        const newVersions = [...selectedProduct.versionColors];
        newVersions[versionIndex].colors[colorIndex].photo = file;
        setSelectedProduct({ ...selectedProduct, versionColors: newVersions });
        setPreviewColorImages({
          ...previewColorImages,
          [`${versionIndex}-${colorIndex}`]: URL.createObjectURL(file)
        });
      }
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Quản lý sản phẩm</h2>
          <p className="text-gray-600">Quản lý danh mục sản phẩm và thông tin chi tiết</p>
        </div>
        <div className="flex space-x-3">
          <button 
            onClick={handleExportProducts}
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
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="h-4 w-4 absolute left-3 top-3 text-gray-400" />
            <input
              type="text"
              placeholder="Tìm kiếm sản phẩm theo tên hoặc mô tả..."
              className="pl-10 pr-4 py-2 w-full border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
              value={productFilter}
              onChange={(e) => setProductFilter(e.target.value)}
            />
          </div>
          <div className="flex space-x-2">
          <select 
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="all">Tất cả danh mục</option>
              {categories.map((category) => (
              <option key={category} value={category}>{category}</option>
            ))}
          </select>
          <select 
            value={brandFilter}
            onChange={(e) => setBrandFilter(e.target.value)}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="all">Tất cả thương hiệu</option>
              {brands.map((brand) => (
              <option key={brand} value={brand}>{brand}</option>
            ))}
          </select>
          <select 
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="all">Tất cả trạng thái</option>
            <option value="ACTIVE">Hoạt động</option>
              <option value="INACTIVE">Ngừng bán</option>
          </select>
          </div>
        </div>
      </div>

      {/* Products Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        {filteredProducts.map((product) => (
          <div key={product.id} className="bg-white rounded-lg shadow-sm border hover:shadow-lg transition-shadow">
              <div className="relative">
                <img
                src={product.avatar ? `http://localhost:8080/api/files/${product.avatar}` : "https://via.placeholder.com/300x200/f3f4f6/9ca3af?text=No+Image"}
                  alt={product.name}
                className="w-full h-48 object-cover rounded-t-lg"
                />
              <div className={`absolute top-2 right-2 px-2 py-1 rounded text-xs font-medium ${
                product.totalStock > 0 ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800"
                  }`}>
                {product.totalStock > 0 ? "Còn hàng" : "Hết hàng"}
                </div>
              </div>

            <div className="p-4">
              <h3 className="font-semibold text-lg text-gray-900 mb-2">{product.name}</h3>
              <p className="text-gray-600 text-sm mb-3 line-clamp-2">{product.description}</p>

              <div className="flex justify-between items-center mb-3">
                <span className="text-xl font-bold text-blue-600">
                  {formatCurrency ? formatCurrency(product.price) : `${product.price} VND`}
                  </span>
                <span className="text-sm text-gray-500">Kho: {product.totalStock || 0}</span>
                </div>

              <div className="flex justify-between items-center text-sm text-gray-600 mb-3">
                <span>Hãng: {product.brandName}</span>
                <span>Dòng: {product.motolineName}</span>
                </div>

                  <div className="flex space-x-2">
                    <button
                  onClick={() => {
                    setSelectedProduct(product);
                    setModalMode("view");
                    setShowProductModal(true);
                  }}
                  className="flex-1 px-3 py-2 text-sm bg-gray-100 text-gray-700 rounded hover:bg-gray-200"
                    >
                  <Eye className="h-4 w-4 inline mr-1" />
                  Xem
                    </button>
                    <button
                  onClick={() => {
                    setSelectedProduct(product);
                    setModalMode("edit");
                    setShowProductModal(true);
                  }}
                  className="flex-1 px-3 py-2 text-sm bg-blue-100 text-blue-700 rounded hover:bg-blue-200"
                    >
                  <Edit className="h-4 w-4 inline mr-1" />
                  Sửa
                    </button>
                    <button
                      onClick={() => handleDeleteProduct(product.id)}
                  className="flex-1 px-3 py-2 text-sm bg-red-100 text-red-700 rounded hover:bg-red-200"
                    >
                  <Trash2 className="h-4 w-4 inline mr-1" />
                  Xóa
                    </button>
                  </div>
                  </div>
                </div>
        ))}
              </div>

      {filteredProducts.length === 0 && (
        <div className="text-center py-12">
          <Package className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-sm font-medium text-gray-900">Không có sản phẩm</h3>
          <p className="mt-1 text-sm text-gray-500">
            {products?.length === 0 ? "Chưa có sản phẩm nào." : "Không tìm thấy sản phẩm phù hợp với bộ lọc."}
          </p>
          </div>
        )}

      {/* Add Product Modal */}
      {showAddProductModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg w-full max-w-4xl max-h-[90vh] overflow-y-auto">
              <div className="p-6">
              <h3 className="text-xl font-semibold mb-4">Thêm sản phẩm mới</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Thông tin cơ bản */}
                    <div className="space-y-4">
                  <h4 className="font-medium text-gray-900">Thông tin cơ bản</h4>
                      <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Tên sản phẩm</label>
                        <input
                          type="text"
                      value={newProduct.name || ""}
                      onChange={(e) => setNewProduct({ ...newProduct, name: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                      </div>
                      <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Mô tả</label>
                        <textarea
                      value={newProduct.description || ""}
                      onChange={(e) => setNewProduct({ ...newProduct, description: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                      rows={3}
                        />
                      </div>
                      <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Giá cơ bản</label>
                        <input
                          type="number"
                      value={newProduct.price || ""}
                      onChange={(e) => setNewProduct({ ...newProduct, price: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Trạng thái</label>
                    <select
                      value={newProduct.status || "ACTIVE"}
                      onChange={(e) => setNewProduct({ ...newProduct, status: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="ACTIVE">Đang bán</option>
                      <option value="INACTIVE">Ngừng bán</option>
                    </select>
                      </div>
                    </div>
                    
                {/* Thông số kỹ thuật */}
                    <div className="space-y-4">
                  <h4 className="font-medium text-gray-900">Thông số kỹ thuật</h4>
                      <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Khối lượng</label>
                        <input
                          type="text"
                      value={newProduct.weight || ""}
                      onChange={(e) => setNewProduct({ ...newProduct, weight: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                      </div>
                      <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Kích thước</label>
                        <input
                          type="text"
                      value={newProduct.size || ""}
                      onChange={(e) => setNewProduct({ ...newProduct, size: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Dung tích bình xăng</label>
                    <input
                      type="text"
                      value={newProduct.petrolCapacity || ""}
                      onChange={(e) => setNewProduct({ ...newProduct, petrolCapacity: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Độ cao yên</label>
                    <input
                      type="text"
                      value={newProduct.saddleHeight || ""}
                      onChange={(e) => setNewProduct({ ...newProduct, saddleHeight: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Kích thước lốp</label>
                    <input
                      type="text"
                      value={newProduct.wheelSize || ""}
                      onChange={(e) => setNewProduct({ ...newProduct, wheelSize: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                  </div>
                      </div>
                      
                {/* Thông số động cơ */}
                <div className="space-y-4">
                  <h4 className="font-medium text-gray-900">Thông số động cơ</h4>
                      <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Loại động cơ</label>
                    <input
                      type="text"
                      value={newProduct.engieType || ""}
                      onChange={(e) => setNewProduct({ ...newProduct, engieType: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Dung tích xi-lanh</label>
                    <input
                      type="text"
                      value={newProduct.cylinderCapacity || ""}
                      onChange={(e) => setNewProduct({ ...newProduct, cylinderCapacity: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Công suất tối đa</label>
                    <input
                      type="text"
                      value={newProduct.maxiumMoment || ""}
                      onChange={(e) => setNewProduct({ ...newProduct, maxiumMoment: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Tỷ số nén</label>
                    <input
                      type="text"
                      value={newProduct.compressionRatio || ""}
                      onChange={(e) => setNewProduct({ ...newProduct, compressionRatio: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                      </div>
                      
                {/* Thông số khác */}
                <div className="space-y-4">
                  <h4 className="font-medium text-gray-900">Thông số khác</h4>
                      <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Dung tích nhớt</label>
                        <input
                          type="text"
                      value={newProduct.oilCapacity || ""}
                      onChange={(e) => setNewProduct({ ...newProduct, oilCapacity: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                      </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Mức tiêu thụ nhiên liệu</label>
                    <input
                      type="text"
                      value={newProduct.fuelConsumption || ""}
                      onChange={(e) => setNewProduct({ ...newProduct, fuelConsumption: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Phuộc trước</label>
                    <input
                      type="text"
                      value={newProduct.beforeFork || ""}
                      onChange={(e) => setNewProduct({ ...newProduct, beforeFork: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Phuộc sau</label>
                    <input
                      type="text"
                      value={newProduct.afterFork || ""}
                      onChange={(e) => setNewProduct({ ...newProduct, afterFork: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                </div>

                {/* Phiên bản và màu sắc */}
                <div className="col-span-2 space-y-4">
                  <h4 className="font-medium text-gray-900">Phiên bản và màu sắc</h4>
                  {newProduct.versionColors.map((version, versionIndex) => (
                    <div key={versionIndex} className="border rounded-lg p-4 space-y-4">
                      <div className="flex justify-between items-center">
                        <h5 className="font-medium">Phiên bản {versionIndex + 1}</h5>
                        <button
                          onClick={() => {
                            const newVersions = [...newProduct.versionColors];
                            newVersions.splice(versionIndex, 1);
                            setNewProduct({ ...newProduct, versionColors: newVersions });
                          }}
                          className="text-red-600 hover:text-red-800"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">Tên phiên bản</label>
                          <input
                            type="text"
                            value={version.versionName}
                            onChange={(e) => {
                              const newVersions = [...newProduct.versionColors];
                              newVersions[versionIndex].versionName = e.target.value;
                              setNewProduct({ ...newProduct, versionColors: newVersions });
                            }}
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">Giá phiên bản</label>
                          <input
                            type="number"
                            value={version.price}
                            onChange={(e) => {
                              const newVersions = [...newProduct.versionColors];
                              newVersions[versionIndex].price = e.target.value;
                              setNewProduct({ ...newProduct, versionColors: newVersions });
                            }}
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                          />
                        </div>
                      </div>
                      <div className="space-y-4">
                        <div className="flex justify-between items-center">
                          <h6 className="font-medium">Màu sắc</h6>
                          <button
                            onClick={() => {
                              const newVersions = [...newProduct.versionColors];
                              newVersions[versionIndex].colors.push({
                                color: "",
                                photo: null,
                                price: "",
                                value: "",
                                quantity: 0
                              });
                              setNewProduct({ ...newProduct, versionColors: newVersions });
                            }}
                            className="text-blue-600 hover:text-blue-800"
                          >
                            <Plus className="h-4 w-4" />
                          </button>
                        </div>
                        {version.colors.map((color, colorIndex) => (
                          <div key={colorIndex} className="grid grid-cols-1 md:grid-cols-5 gap-4">
                            <div>
                              <label className="block text-sm font-medium text-gray-700 mb-1">Hình ảnh màu</label>
                              <div className="relative">
                                <img
                                  src={previewColorImages[`${versionIndex}-${colorIndex}`] || defaultImage}
                                  alt="Color preview"
                                  className="h-20 w-20 object-cover rounded-lg"
                                />
                                <label
                                  htmlFor={`color-image-upload-${versionIndex}-${colorIndex}`}
                                  className="absolute inset-0 flex items-center justify-center bg-black bg-opacity-50 rounded-lg cursor-pointer opacity-0 hover:opacity-100 transition-opacity"
                                >
                                  <Camera className="h-4 w-4 text-white" />
                        </label>
                                <input
                                  id={`color-image-upload-${versionIndex}-${colorIndex}`}
                                  type="file"
                                  accept="image/*"
                                  className="hidden"
                                  onChange={(e) => handleImageUpload(e, 'color', versionIndex, colorIndex)}
                                />
                              </div>
                            </div>
                            <div>
                              <label className="block text-sm font-medium text-gray-700 mb-1">Tên màu</label>
                        <input
                          type="text"
                                value={color.color}
                                onChange={(e) => {
                                  const newVersions = [...newProduct.versionColors];
                                  newVersions[versionIndex].colors[colorIndex].color = e.target.value;
                                  setNewProduct({ ...newProduct, versionColors: newVersions });
                                }}
                                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                              />
                            </div>
                            <div>
                              <label className="block text-sm font-medium text-gray-700 mb-1">Giá màu</label>
                              <input
                                type="number"
                                value={color.price}
                                onChange={(e) => {
                                  const newVersions = [...newProduct.versionColors];
                                  newVersions[versionIndex].colors[colorIndex].price = e.target.value;
                                  setNewProduct({ ...newProduct, versionColors: newVersions });
                                }}
                                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                              />
                            </div>
                            <div>
                              <label className="block text-sm font-medium text-gray-700 mb-1">Số lượng</label>
                              <input
                                type="number"
                                value={color.quantity}
                                onChange={(e) => {
                                  const newVersions = [...newProduct.versionColors];
                                  newVersions[versionIndex].colors[colorIndex].quantity = parseInt(e.target.value);
                                  setNewProduct({ ...newProduct, versionColors: newVersions });
                                }}
                                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                              />
                            </div>
                            <div className="flex items-end">
                              <button
                                onClick={() => {
                                  const newVersions = [...newProduct.versionColors];
                                  newVersions[versionIndex].colors.splice(colorIndex, 1);
                                  setNewProduct({ ...newProduct, versionColors: newVersions });
                                }}
                                className="text-red-600 hover:text-red-800"
                              >
                                <Trash2 className="h-4 w-4" />
                              </button>
                            </div>
                      </div>
                    ))}
                  </div>
                    </div>
                  ))}
                  <button
                    onClick={() => {
                      setNewProduct({
                        ...newProduct,
                        versionColors: [
                          ...newProduct.versionColors,
                          {
                            versionName: "",
                            price: "",
                            colors: [
                              {
                                color: "",
                                photo: null,
                                price: "",
                                value: "",
                                quantity: 0
                              }
                            ]
                          }
                        ]
                      });
                    }}
                    className="w-full px-4 py-2 border-2 border-dashed border-gray-300 rounded-lg text-gray-600 hover:border-gray-400 hover:text-gray-700"
                  >
                    <Plus className="h-4 w-4 inline mr-2" />
                    Thêm phiên bản
                  </button>
              </div>
            </div>

              <div className="mt-6 flex justify-end space-x-3">
              <button
                onClick={() => setShowAddProductModal(false)}
                  className="px-4 py-2 text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200"
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
        </div>
      )}

      {/* View/Edit Product Modal */}
      {showProductModal && selectedProduct && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="p-6">
              <h3 className="text-xl font-semibold mb-4">
                {modalMode === "view" ? "Chi tiết sản phẩm" : "Chỉnh sửa sản phẩm"}
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Thông tin cơ bản */}
            <div className="space-y-4">
                  <h4 className="font-medium text-gray-900">Thông tin cơ bản</h4>
              <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Tên sản phẩm</label>
                <input
                  type="text"
                      value={selectedProduct.name || ""}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, name: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                />
              </div>
              <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Mô tả</label>
                <textarea
                      value={selectedProduct.description || ""}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, description: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                  rows={3}
                />
              </div>
              <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Giá cơ bản</label>
                <input
                  type="number"
                      value={selectedProduct.price || ""}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, price: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Trạng thái</label>
                    <select
                      value={selectedProduct.status || "ACTIVE"}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, status: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                    >
                      <option value="ACTIVE">Đang bán</option>
                      <option value="INACTIVE">Ngừng bán</option>
                    </select>
                  </div>
              </div>
              
                {/* Thông số kỹ thuật */}
                <div className="space-y-4">
                  <h4 className="font-medium text-gray-900">Thông số kỹ thuật</h4>
              <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Khối lượng</label>
                <input
                  type="text"
                      value={selectedProduct.weight || ""}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, weight: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Kích thước</label>
                    <input
                      type="text"
                      value={selectedProduct.size || ""}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, size: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Dung tích bình xăng</label>
                    <input
                      type="text"
                      value={selectedProduct.petrolCapacity || ""}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, petrolCapacity: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Độ cao yên</label>
                    <input
                      type="text"
                      value={selectedProduct.saddleHeight || ""}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, saddleHeight: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Kích thước lốp</label>
                    <input
                      type="text"
                      value={selectedProduct.wheelSize || ""}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, wheelSize: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                    />
                  </div>
              </div>
              
                {/* Thông số động cơ */}
                <div className="space-y-4">
                  <h4 className="font-medium text-gray-900">Thông số động cơ</h4>
              <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Loại động cơ</label>
                <input
                  type="text"
                      value={selectedProduct.engieType || ""}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, engieType: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Dung tích xi-lanh</label>
                    <input
                      type="text"
                      value={selectedProduct.cylinderCapacity || ""}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, cylinderCapacity: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Công suất tối đa</label>
                    <input
                      type="text"
                      value={selectedProduct.maxiumCapacity || ""}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, maxiumCapacity: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Mô-men xoắn tối đa</label>
                    <input
                      type="text"
                      value={selectedProduct.maxiumMoment || ""}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, maxiumMoment: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Tỷ số nén</label>
                    <input
                      type="text"
                      value={selectedProduct.compressionRatio || ""}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, compressionRatio: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                    />
                  </div>
              </div>
              
                {/* Thông số khác */}
                <div className="space-y-4">
                  <h4 className="font-medium text-gray-900">Thông số khác</h4>
              <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Dung tích nhớt</label>
                    <input
                      type="text"
                      value={selectedProduct.oilCapacity || ""}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, oilCapacity: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Mức tiêu thụ nhiên liệu</label>
                    <input
                      type="text"
                      value={selectedProduct.fuelConsumption || ""}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, fuelConsumption: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Phuộc trước</label>
                    <input
                      type="text"
                      value={selectedProduct.beforeFork || ""}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, beforeFork: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Phuộc sau</label>
                    <input
                      type="text"
                      value={selectedProduct.afterFork || ""}
                      onChange={(e) => setSelectedProduct({ ...selectedProduct, afterFork: e.target.value })}
                      disabled={modalMode === "view"}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
                    />
                  </div>
                </div>

                {/* Phiên bản và màu sắc */}
                {modalMode === "edit" && (
                  <div className="col-span-2 space-y-4">
                    <h4 className="font-medium text-gray-900">Phiên bản và màu sắc</h4>
                    {selectedProduct.versionColors?.map((version, versionIndex) => (
                      <div key={versionIndex} className="border rounded-lg p-4 space-y-4">
                        <div className="flex justify-between items-center">
                          <h5 className="font-medium">Phiên bản {versionIndex + 1}</h5>
                          <button
                            onClick={() => {
                              const newVersions = [...selectedProduct.versionColors];
                              newVersions.splice(versionIndex, 1);
                              setSelectedProduct({ ...selectedProduct, versionColors: newVersions });
                            }}
                            className="text-red-600 hover:text-red-800"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">Tên phiên bản</label>
                            <input
                              type="text"
                              value={version.versionName}
                              onChange={(e) => {
                                const newVersions = [...selectedProduct.versionColors];
                                newVersions[versionIndex].versionName = e.target.value;
                                setSelectedProduct({ ...selectedProduct, versionColors: newVersions });
                              }}
                              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">Giá phiên bản</label>
                            <input
                              type="number"
                              value={version.price}
                              onChange={(e) => {
                                const newVersions = [...selectedProduct.versionColors];
                                newVersions[versionIndex].price = e.target.value;
                                setSelectedProduct({ ...selectedProduct, versionColors: newVersions });
                              }}
                              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                            />
                          </div>
                        </div>
                        <div className="space-y-4">
                          <div className="flex justify-between items-center">
                            <h6 className="font-medium">Màu sắc</h6>
                            <button
                              onClick={() => {
                                const newVersions = [...selectedProduct.versionColors];
                                newVersions[versionIndex].colors.push({
                                  color: "",
                                  photo: null,
                                  price: "",
                                  value: "",
                                  quantity: 0
                                });
                                setSelectedProduct({ ...selectedProduct, versionColors: newVersions });
                              }}
                              className="text-blue-600 hover:text-blue-800"
                            >
                              <Plus className="h-4 w-4" />
                            </button>
                          </div>
                          {version.colors?.map((color, colorIndex) => (
                            <div key={colorIndex} className="grid grid-cols-1 md:grid-cols-5 gap-4">
                              <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">Hình ảnh màu</label>
                                <div className="relative">
                                  <img
                                    src={previewColorImages[`${versionIndex}-${colorIndex}`] || (color.photo ? `http://localhost:8080/api/files/${color.photo}` : defaultImage)}
                                    alt="Color preview"
                                    className="h-20 w-20 object-cover rounded-lg"
                                  />
                                  <label
                                    htmlFor={`edit-color-image-upload-${versionIndex}-${colorIndex}`}
                                    className="absolute inset-0 flex items-center justify-center bg-black bg-opacity-50 rounded-lg cursor-pointer opacity-0 hover:opacity-100 transition-opacity"
                                  >
                                    <Camera className="h-4 w-4 text-white" />
                </label>
                                  <input
                                    id={`edit-color-image-upload-${versionIndex}-${colorIndex}`}
                                    type="file"
                                    accept="image/*"
                                    className="hidden"
                                    onChange={(e) => handleProductImageUpload(e, 'color', versionIndex, colorIndex)}
                                  />
                                </div>
                              </div>
                              <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">Tên màu</label>
                                <input
                                  type="text"
                                  value={color.color}
                                  onChange={(e) => {
                                    const newVersions = [...selectedProduct.versionColors];
                                    newVersions[versionIndex].colors[colorIndex].color = e.target.value;
                                    setSelectedProduct({ ...selectedProduct, versionColors: newVersions });
                                  }}
                                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                                />
                              </div>
                              <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">Giá màu</label>
                                <input
                                  type="number"
                                  value={color.price}
                                  onChange={(e) => {
                                    const newVersions = [...selectedProduct.versionColors];
                                    newVersions[versionIndex].colors[colorIndex].price = e.target.value;
                                    setSelectedProduct({ ...selectedProduct, versionColors: newVersions });
                                  }}
                                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                                />
                              </div>
                              <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">Số lượng</label>
                                <input
                                  type="number"
                                  value={color.quantity}
                                  onChange={(e) => {
                                    const newVersions = [...selectedProduct.versionColors];
                                    newVersions[versionIndex].colors[colorIndex].quantity = parseInt(e.target.value);
                                    setSelectedProduct({ ...selectedProduct, versionColors: newVersions });
                                  }}
                                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                                />
                              </div>
                              <div className="flex items-end">
                                <button
                                  onClick={() => {
                                    const newVersions = [...selectedProduct.versionColors];
                                    newVersions[versionIndex].colors.splice(colorIndex, 1);
                                    setSelectedProduct({ ...selectedProduct, versionColors: newVersions });
                                  }}
                                  className="text-red-600 hover:text-red-800"
                                >
                                  <Trash2 className="h-4 w-4" />
                                </button>
              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                    <button
                      onClick={() => {
                        setSelectedProduct({
                          ...selectedProduct,
                          versionColors: [
                            ...(selectedProduct.versionColors || []),
                            {
                              versionName: "",
                              price: "",
                              colors: [
                                {
                                  color: "",
                                  photo: null,
                                  price: "",
                                  value: "",
                                  quantity: 0
                                }
                              ]
                            }
                          ]
                        });
                      }}
                      className="w-full px-4 py-2 border-2 border-dashed border-gray-300 rounded-lg text-gray-600 hover:border-gray-400 hover:text-gray-700"
                    >
                      <Plus className="h-4 w-4 inline mr-2" />
                      Thêm phiên bản
                    </button>
                  </div>
                )}
            </div>
            
              <div className="mt-6 flex justify-end space-x-3">
              <button
                onClick={() => setShowProductModal(false)}
                  className="px-4 py-2 text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200"
              >
                  Đóng
              </button>
                {modalMode === "edit" && (
                  <>
                <button
                      onClick={() => handleDeleteProduct(selectedProduct.id)}
                      className="px-4 py-2 text-red-700 bg-red-100 rounded-lg hover:bg-red-200"
                >
                      Xóa
                </button>
                <button
                  onClick={handleSaveProduct}
                      className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Lưu thay đổi
                </button>
                  </>
              )}
              </div>
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
  const totalRevenue = orders?.reduce((sum, order) => sum + (order.totalAmount || 0), 0) || 0;
  const totalOrders = orders?.length || 0;
  const totalUsers = users?.length || 0;
  const pendingOrders = orders?.filter(o => o.status === "PENDING").length || 0;
  const deliveredOrders = orders?.filter(o => o.status === "DELIVERED").length || 0;
  
  // Calculate monthly data for last 6 months
  const getMonthlyData = () => {
    const months = [];
    const now = new Date();
    
    for (let i = 5; i >= 0; i--) {
      const date = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const monthName = date.toLocaleDateString('vi-VN', { month: 'short', year: 'numeric' });
      
      const monthOrders = orders?.filter(order => {
        const orderDate = new Date(order.orderDate);
        return orderDate.getMonth() === date.getMonth() && 
               orderDate.getFullYear() === date.getFullYear();
      }) || [];
      
      months.push({
        name: monthName,
        orders: monthOrders.length,
        revenue: monthOrders.reduce((sum, order) => sum + (order.totalAmount || 0), 0)
      });
    }
    
    return months;
  };

  const monthlyData = getMonthlyData();
  const averageOrderValue = totalOrders > 0 ? totalRevenue / totalOrders : 0;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Thống kê & Báo cáo</h2>
        <p className="text-gray-600">
          Phân tích dữ liệu và báo cáo hoạt động kinh doanh
        </p>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <div className="flex items-center">
            <div className="p-3 bg-green-100 rounded-full">
              <DollarSign className="h-8 w-8 text-green-600" />
          </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Tổng doanh thu</p>
              <p className="text-2xl font-bold text-gray-900">
                {formatCurrency ? formatCurrency(totalRevenue) : `${totalRevenue.toLocaleString()} VND`}
              </p>
              <p className="text-sm text-green-600">+12.5% so với tháng trước</p>
        </div>
          </div>
                      </div>
                      
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <div className="flex items-center">
            <div className="p-3 bg-blue-100 rounded-full">
              <ShoppingCart className="h-8 w-8 text-blue-600" />
          </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Tổng đơn hàng</p>
              <p className="text-2xl font-bold text-gray-900">{totalOrders}</p>
              <p className="text-sm text-blue-600">+8.3% so với tháng trước</p>
        </div>
      </div>
    </div>

        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <div className="flex items-center">
            <div className="p-3 bg-purple-100 rounded-full">
              <Users className="h-8 w-8 text-purple-600" />
                      </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Tổng người dùng</p>
              <p className="text-2xl font-bold text-gray-900">{totalUsers}</p>
              <p className="text-sm text-purple-600">+15.2% so với tháng trước</p>
                  </div>
              </div>
      </div>

      <div className="bg-white p-6 rounded-lg shadow-sm border">
          <div className="flex items-center">
            <div className="p-3 bg-orange-100 rounded-full">
              <TrendingUp className="h-8 w-8 text-orange-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Giá trị đơn TB</p>
              <p className="text-2xl font-bold text-gray-900">
                {formatCurrency ? formatCurrency(averageOrderValue) : `${Math.round(averageOrderValue).toLocaleString()} VND`}
              </p>
              <p className="text-sm text-orange-600">+5.7% so với tháng trước</p>
          </div>
        </div>
            </div>
              </div>
              
      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Revenue Chart */}
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Doanh thu 6 tháng gần đây</h3>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={monthlyData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis 
                  dataKey="name" 
                  tick={{ fontSize: 12 }}
                  axisLine={{ stroke: '#e0e7ff' }}
                />
                <YAxis 
                  tick={{ fontSize: 12 }}
                  axisLine={{ stroke: '#e0e7ff' }}
                  tickFormatter={(value) => `${(value / 1000000).toFixed(1)}M`}
                />
                <Tooltip 
                  formatter={(value, name) => [
                    formatCurrency ? formatCurrency(value) : `${value.toLocaleString()} VND`,
                    name === 'revenue' ? 'Doanh thu' : 'Đơn hàng'
                  ]}
                  labelStyle={{ color: '#374151' }}
                  contentStyle={{ 
                    backgroundColor: '#f9fafb', 
                    border: '1px solid #e5e7eb',
                    borderRadius: '8px'
                  }}
                />
                <Legend />
                <defs>
                  <linearGradient id="colorRevenue" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.1}/>
                  </linearGradient>
                </defs>
                <Area 
                  type="monotone" 
                  dataKey="revenue" 
                  stroke="#3b82f6" 
                  strokeWidth={2}
                  fillOpacity={1} 
                  fill="url(#colorRevenue)"
                  name="Doanh thu"
            />
              </AreaChart>
            </ResponsiveContainer>
          </div>
              </div>
              
        {/* Order Status Distribution */}
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Phân bố trạng thái đơn hàng</h3>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={[
                    { name: 'Đã giao', value: deliveredOrders, color: '#10b981' },
                    { name: 'Chờ xử lý', value: pendingOrders, color: '#f59e0b' },
                    { name: 'Đang xử lý', value: orders?.filter(o => o.status === "PROCESSING").length || 0, color: '#3b82f6' },
                    { name: 'Đã hủy', value: orders?.filter(o => o.status === "CANCELLED").length || 0, color: '#ef4444' }
                  ].filter(item => item.value > 0)}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {[
                    { name: 'Đã giao', value: deliveredOrders, color: '#10b981' },
                    { name: 'Chờ xử lý', value: pendingOrders, color: '#f59e0b' },
                    { name: 'Đang xử lý', value: orders?.filter(o => o.status === "PROCESSING").length || 0, color: '#3b82f6' },
                    { name: 'Đã hủy', value: orders?.filter(o => o.status === "CANCELLED").length || 0, color: '#ef4444' }
                  ].filter(item => item.value > 0).map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  formatter={(value) => [`${value} đơn`, 'Số lượng']}
                  labelStyle={{ color: '#374151' }}
                  contentStyle={{ 
                    backgroundColor: '#f9fafb', 
                    border: '1px solid #e5e7eb',
                    borderRadius: '8px'
                  }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
              </div>
            </div>
            
      {/* Additional Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Monthly Orders Chart */}
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Số đơn hàng theo tháng</h3>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={monthlyData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis 
                  dataKey="name" 
                  tick={{ fontSize: 12 }}
                  axisLine={{ stroke: '#e0e7ff' }}
                />
                <YAxis 
                  tick={{ fontSize: 12 }}
                  axisLine={{ stroke: '#e0e7ff' }}
                />
                <Tooltip 
                  formatter={(value) => [`${value} đơn`, 'Số đơn hàng']}
                  labelStyle={{ color: '#374151' }}
                  contentStyle={{ 
                    backgroundColor: '#f9fafb', 
                    border: '1px solid #e5e7eb',
                    borderRadius: '8px'
                  }}
                />
                <Legend />
                <Bar 
                  dataKey="orders" 
                  fill="#8b5cf6" 
                  name="Số đơn hàng"
                  radius={[4, 4, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
            </div>
          </div>

        {/* Revenue vs Orders Comparison */}
        <div className="bg-white p-6 rounded-lg shadow-sm border">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Doanh thu & Đơn hàng</h3>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={monthlyData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis 
                  dataKey="name" 
                  tick={{ fontSize: 12 }}
                  axisLine={{ stroke: '#e0e7ff' }}
                />
                <YAxis 
                  yAxisId="left"
                  tick={{ fontSize: 12 }}
                  axisLine={{ stroke: '#e0e7ff' }}
                  tickFormatter={(value) => `${(value / 1000000).toFixed(1)}M`}
                />
                <YAxis 
                  yAxisId="right" 
                  orientation="right"
                  tick={{ fontSize: 12 }}
                  axisLine={{ stroke: '#e0e7ff' }}
                />
                <Tooltip 
                  formatter={(value, name) => [
                    name === 'revenue' 
                      ? (formatCurrency ? formatCurrency(value) : `${value.toLocaleString()} VND`)
                      : `${value} đơn`,
                    name === 'revenue' ? 'Doanh thu' : 'Số đơn hàng'
                  ]}
                  labelStyle={{ color: '#374151' }}
                  contentStyle={{ 
                    backgroundColor: '#f9fafb', 
                    border: '1px solid #e5e7eb',
                    borderRadius: '8px'
                  }}
                />
                <Legend />
                <Line 
                  yAxisId="left"
                  type="monotone" 
                  dataKey="revenue" 
                  stroke="#10b981" 
                  strokeWidth={3}
                  dot={{ fill: '#10b981', strokeWidth: 2, r: 4 }}
                  name="Doanh thu"
                />
                <Line 
                  yAxisId="right"
                  type="monotone" 
                  dataKey="orders" 
                  stroke="#f59e0b" 
                  strokeWidth={3}
                  dot={{ fill: '#f59e0b', strokeWidth: 2, r: 4 }}
                  name="Số đơn hàng"
                />
              </LineChart>
            </ResponsiveContainer>
        </div>
    </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-white rounded-lg shadow-sm border">
        <div className="p-6 border-b">
          <h3 className="text-lg font-semibold text-gray-900">Hoạt động gần đây</h3>
          </div>
        <div className="p-6">
          <div className="space-y-4">
            {orders?.slice(0, 5).map((order, index) => (
              <div key={index} className="flex items-center space-x-4">
                <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                <div className="flex-1">
                  <p className="text-sm text-gray-900">
                    Đơn hàng #{order.id} từ {order.user?.username || "Khách hàng"}
                  </p>
                  <p className="text-xs text-gray-500">
                    {formatCurrency ? formatCurrency(order.totalAmount) : `${order.totalAmount} VND`} - 
                    {order.status === "PENDING" ? " Chờ xử lý" : 
                     order.status === "DELIVERED" ? " Đã giao" : ` ${order.status}`}
                  </p>
        </div>
                <div className="text-xs text-gray-500">
                  {new Date(order.orderDate).toLocaleDateString('vi-VN')}
                </div>
              </div>
            ))}
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
        <p className="text-gray-600">
          Quản lý cấu hình và thiết lập hệ thống
        </p>
      </div>
      <div>Các tùy chọn cài đặt đang được khôi phục...</div>
    </div>
  );
}; 