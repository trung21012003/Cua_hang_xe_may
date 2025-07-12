import React, { useContext, useState, useEffect } from 'react';
import { UserContext } from '../contexts/GetUser';
import axios from 'axios';

const RoleBasedComponent = () => {
  const { user, isLoggedIn } = useContext(UserContext);
  const [users, setUsers] = useState([]);
  const [orders, setOrders] = useState([]);
  const [systemStats, setSystemStats] = useState(null);
  const [loading, setLoading] = useState(false);

  // Helper function to check user role
  const hasRole = (requiredRole) => {
    if (!user || !user.role) return false;
    
    switch (requiredRole) {
      case 'ADMIN':
        return user.role === '0';
      case 'MANAGER':
        return user.role === '2';
      case 'USER':
        return user.role === '1';
      case 'ADMIN_OR_MANAGER':
        return user.role === '0' || user.role === '2';
      default:
        return false;
    }
  };

  // Get role display name
  const getRoleDisplayName = (roleCode) => {
    switch (roleCode) {
      case '0': return 'Admin';
      case '1': return 'User';
      case '2': return 'Manager';
      case '3': return 'Guest';
      default: return 'Unknown';
    }
  };

  // Fetch system statistics (Admin only)
  const fetchSystemStats = async () => {
    if (!hasRole('ADMIN')) return;
    
    setLoading(true);
    try {
      const token = localStorage.getItem('jwtToken');
      const response = await axios.get('http://localhost:8080/api/admin/stats', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSystemStats(response.data);
    } catch (error) {
      console.error('Error fetching system stats:', error);
      alert('Failed to fetch system statistics');
    } finally {
      setLoading(false);
    }
  };

  // Fetch all users (Admin only)
  const fetchAllUsers = async () => {
    if (!hasRole('ADMIN')) return;
    
    setLoading(true);
    try {
      const token = localStorage.getItem('jwtToken');
      const response = await axios.get('http://localhost:8080/api/admin/users', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setUsers(response.data.content || response.data);
    } catch (error) {
      console.error('Error fetching users:', error);
      alert('Failed to fetch users');
    } finally {
      setLoading(false);
    }
  };

  // Fetch all orders (Admin/Manager only)
  const fetchAllOrders = async () => {
    if (!hasRole('ADMIN_OR_MANAGER')) return;
    
    setLoading(true);
    try {
      const token = localStorage.getItem('jwtToken');
      const response = await axios.get('http://localhost:8080/api/orders/admin/all', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setOrders(response.data.content || response.data);
    } catch (error) {
      console.error('Error fetching orders:', error);
      alert('Failed to fetch orders');
    } finally {
      setLoading(false);
    }
  };

  // Update user role (Admin only)
  const updateUserRole = async (userId, newRole) => {
    if (!hasRole('ADMIN')) return;
    
    try {
      const token = localStorage.getItem('jwtToken');
      await axios.put(`http://localhost:8080/api/admin/users/${userId}/role?roleCode=${newRole}`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      alert('User role updated successfully!');
      fetchAllUsers(); // Refresh the user list
    } catch (error) {
      console.error('Error updating user role:', error);
      alert('Failed to update user role');
    }
  };

  // Update order status (Admin/Manager only)
  const updateOrderStatus = async (orderId, newStatus) => {
    if (!hasRole('ADMIN_OR_MANAGER')) return;
    
    try {
      const token = localStorage.getItem('jwtToken');
      await axios.put(`http://localhost:8080/api/orders/admin/${orderId}/status?status=${newStatus}`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      alert('Order status updated successfully!');
      fetchAllOrders(); // Refresh the order list
    } catch (error) {
      console.error('Error updating order status:', error);
      alert('Failed to update order status');
    }
  };

  if (!isLoggedIn) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="bg-yellow-100 border border-yellow-400 text-yellow-700 px-4 py-3 rounded">
          Vui lòng đăng nhập để xem nội dung này.
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="bg-white rounded-lg shadow-md p-6">
        {/* User Info Header */}
        <div className="mb-6 p-4 bg-blue-50 rounded-lg">
          <h2 className="text-2xl font-bold text-blue-800 mb-2">
            Role-Based Dashboard
          </h2>
          <div className="flex items-center space-x-4">
            <span className="text-lg">
              <strong>User:</strong> {user?.username || 'Unknown'}
            </span>
            <span className={`px-3 py-1 rounded-full text-sm font-semibold ${
              hasRole('ADMIN') ? 'bg-red-100 text-red-800' :
              hasRole('MANAGER') ? 'bg-yellow-100 text-yellow-800' :
              hasRole('USER') ? 'bg-green-100 text-green-800' :
              'bg-gray-100 text-gray-800'
            }`}>
              {getRoleDisplayName(user?.role)}
            </span>
          </div>
        </div>

        {/* Admin Only Section */}
        {hasRole('ADMIN') && (
          <div className="mb-8 p-4 border-2 border-red-200 rounded-lg bg-red-50">
            <h3 className="text-xl font-bold text-red-800 mb-4 flex items-center">
              🔴 Admin Only Features
            </h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-4">
              <button
                onClick={fetchSystemStats}
                disabled={loading}
                className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded disabled:opacity-50"
              >
                {loading ? 'Loading...' : 'Get System Stats'}
              </button>
              
              <button
                onClick={fetchAllUsers}
                disabled={loading}
                className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded disabled:opacity-50"
              >
                {loading ? 'Loading...' : 'Get All Users'}
              </button>
            </div>

            {/* System Stats Display */}
            {systemStats && (
              <div className="bg-white p-4 rounded border mb-4">
                <h4 className="font-bold mb-2">System Statistics</h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>Total Users: <strong>{systemStats.totalUsers}</strong></div>
                  <div>Active Users: <strong>{systemStats.activeUsers}</strong></div>
                  <div>Pending Users: <strong>{systemStats.pendingUsers}</strong></div>
                  <div>Inactive Users: <strong>{systemStats.inactiveUsers}</strong></div>
                  <div>Admins: <strong>{systemStats.adminCount}</strong></div>
                  <div>Users: <strong>{systemStats.userCount}</strong></div>
                  <div>Managers: <strong>{systemStats.managerCount}</strong></div>
                  <div>Guests: <strong>{systemStats.guestCount}</strong></div>
                </div>
              </div>
            )}

            {/* Users Management */}
            {users.length > 0 && (
              <div className="bg-white p-4 rounded border">
                <h4 className="font-bold mb-2">User Management</h4>
                <div className="overflow-x-auto">
                  <table className="min-w-full table-auto">
                    <thead>
                      <tr className="bg-gray-100">
                        <th className="px-4 py-2 text-left">Username</th>
                        <th className="px-4 py-2 text-left">Email</th>
                        <th className="px-4 py-2 text-left">Role</th>
                        <th className="px-4 py-2 text-left">Status</th>
                        <th className="px-4 py-2 text-left">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {users.slice(0, 5).map((user) => (
                        <tr key={user.id} className="border-b">
                          <td className="px-4 py-2">{user.username}</td>
                          <td className="px-4 py-2">{user.email}</td>
                          <td className="px-4 py-2">{getRoleDisplayName(user.role)}</td>
                          <td className="px-4 py-2">
                            <span className={`px-2 py-1 rounded text-xs ${
                              user.status === 'ACTIVE' ? 'bg-green-100 text-green-800' :
                              user.status === 'PENDING' ? 'bg-yellow-100 text-yellow-800' :
                              'bg-red-100 text-red-800'
                            }`}>
                              {user.status}
                            </span>
                          </td>
                          <td className="px-4 py-2">
                            <select
                              onChange={(e) => updateUserRole(user.id, e.target.value)}
                              className="text-xs border rounded px-2 py-1"
                              defaultValue={user.role}
                            >
                              <option value="0">Admin</option>
                              <option value="1">User</option>
                              <option value="2">Manager</option>
                              <option value="3">Guest</option>
                            </select>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Admin & Manager Section */}
        {hasRole('ADMIN_OR_MANAGER') && (
          <div className="mb-8 p-4 border-2 border-yellow-200 rounded-lg bg-yellow-50">
            <h3 className="text-xl font-bold text-yellow-800 mb-4 flex items-center">
              🟡 Admin & Manager Features
            </h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <button
                onClick={fetchAllOrders}
                disabled={loading}
                className="bg-yellow-600 hover:bg-yellow-700 text-white px-4 py-2 rounded disabled:opacity-50"
              >
                {loading ? 'Loading...' : 'Get All Orders'}
              </button>
            </div>

            {/* Orders Management */}
            {orders.length > 0 && (
              <div className="bg-white p-4 rounded border">
                <h4 className="font-bold mb-2">Order Management</h4>
                <div className="overflow-x-auto">
                  <table className="min-w-full table-auto">
                    <thead>
                      <tr className="bg-gray-100">
                        <th className="px-4 py-2 text-left">Order ID</th>
                        <th className="px-4 py-2 text-left">Customer</th>
                        <th className="px-4 py-2 text-left">Total</th>
                        <th className="px-4 py-2 text-left">Status</th>
                        <th className="px-4 py-2 text-left">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {orders.slice(0, 5).map((order) => (
                        <tr key={order.id} className="border-b">
                          <td className="px-4 py-2">#{order.id}</td>
                          <td className="px-4 py-2">{order.user?.username || 'Unknown'}</td>
                          <td className="px-4 py-2">${order.totalAmount}</td>
                          <td className="px-4 py-2">
                            <span className={`px-2 py-1 rounded text-xs ${
                              order.status === 'DELIVERED' ? 'bg-green-100 text-green-800' :
                              order.status === 'SHIPPED' ? 'bg-blue-100 text-blue-800' :
                              order.status === 'PROCESSING' ? 'bg-yellow-100 text-yellow-800' :
                              'bg-gray-100 text-gray-800'
                            }`}>
                              {order.status}
                            </span>
                          </td>
                          <td className="px-4 py-2">
                            <select
                              onChange={(e) => updateOrderStatus(order.id, e.target.value)}
                              className="text-xs border rounded px-2 py-1"
                              defaultValue={order.status}
                            >
                              <option value="PENDING">Pending</option>
                              <option value="CONFIRMED">Confirmed</option>
                              <option value="PROCESSING">Processing</option>
                              <option value="SHIPPED">Shipped</option>
                              <option value="DELIVERED">Delivered</option>
                              <option value="CANCELLED">Cancelled</option>
                            </select>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* User Section */}
        <div className="p-4 border-2 border-green-200 rounded-lg bg-green-50">
          <h3 className="text-xl font-bold text-green-800 mb-4 flex items-center">
            🟢 User Features (Available to all authenticated users)
          </h3>
          
          <div className="space-y-4">
            <div className="bg-white p-4 rounded border">
              <h4 className="font-bold mb-2">Your Account Information</h4>
              <div className="space-y-2 text-sm">
                <div><strong>Username:</strong> {user?.username}</div>
                <div><strong>Email:</strong> {user?.email}</div>
                <div><strong>Name:</strong> {user?.name || 'Not set'}</div>
                <div><strong>Role:</strong> {getRoleDisplayName(user?.role)}</div>
                <div><strong>Status:</strong> {user?.status}</div>
              </div>
            </div>
            
            <div className="bg-white p-4 rounded border">
              <h4 className="font-bold mb-2">Available Actions</h4>
              <div className="space-y-2">
                <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded mr-2">
                  View My Profile
                </button>
                <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded mr-2">
                  View My Orders
                </button>
                <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded">
                  Update Profile
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Access Denied Section for demonstration */}
        <div className="mt-8 p-4 border-2 border-gray-200 rounded-lg bg-gray-50">
          <h3 className="text-xl font-bold text-gray-800 mb-4">
            🚫 Restricted Content Examples
          </h3>
          
          {!hasRole('ADMIN') && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-2">
              ❌ Admin panel - Access denied. Admin role required.
            </div>
          )}
          
          {!hasRole('ADMIN_OR_MANAGER') && (
            <div className="bg-yellow-100 border border-yellow-400 text-yellow-700 px-4 py-3 rounded mb-2">
              ⚠️ Order management - Access denied. Manager or Admin role required.
            </div>
          )}
          
          <div className="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded">
            ✅ User profile - Access granted. All authenticated users can access.
          </div>
        </div>
      </div>
    </div>
  );
};

export default RoleBasedComponent; 