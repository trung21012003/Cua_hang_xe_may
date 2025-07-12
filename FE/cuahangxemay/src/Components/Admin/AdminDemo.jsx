import React, { useState, useContext } from 'react';
import { UserContext } from '../contexts/GetUser';
import axios from 'axios';

const AdminDemo = () => {
  const { user } = useContext(UserContext);
  const [testResults, setTestResults] = useState([]);
  const [loading, setLoading] = useState(false);

  const runAdminTests = async () => {
    setLoading(true);
    const results = [];
    const token = localStorage.getItem('jwtToken');

    const tests = [
      {
        name: 'Get System Stats',
        url: 'http://localhost:8080/api/admin/stats',
        method: 'GET'
      },
      {
        name: 'Get All Users',
        url: 'http://localhost:8080/api/admin/users?page=0&size=10',
        method: 'GET'
      },
      {
        name: 'Get All Orders (Admin)',
        url: 'http://localhost:8080/api/orders/admin/all?page=0&size=10',
        method: 'GET'
      },
      {
        name: 'Get Products (Manager)',
        url: 'http://localhost:8080/api/products/manage',
        method: 'GET'
      }
    ];

    for (const test of tests) {
      try {
        const response = await axios({
          method: test.method,
          url: test.url,
          headers: { Authorization: `Bearer ${token}` }
        });
        
        results.push({
          name: test.name,
          status: 'SUCCESS',
          data: response.data,
          statusCode: response.status
        });
      } catch (error) {
        results.push({
          name: test.name,
          status: 'ERROR',
          error: error.response?.data || error.message,
          statusCode: error.response?.status || 'N/A'
        });
      }
    }

    setTestResults(results);
    setLoading(false);
  };

  const isAdmin = () => {
    return user && user.role === '0';
  };

  if (!isAdmin()) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
                 <div className="bg-white p-8 rounded-lg shadow-md">
           <h2 className="text-2xl font-bold text-red-600 mb-4">Truy cập bị từ chối</h2>
           <p className="text-gray-600">Bạn cần quyền quản trị viên để truy cập trang demo này.</p>
         </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100 p-8">
      <div className="max-w-6xl mx-auto">
        <div className="bg-white rounded-lg shadow-md p-6 mb-8">
                     <h1 className="text-3xl font-bold text-gray-900 mb-2">Demo Bảng điều khiển Quản trị</h1>
           <p className="text-gray-600 mb-4">
             Chào mừng, {user.username}! Kiểm tra quyền truy cập quản trị viên của bạn.
           </p>
          
          <div className="flex space-x-4 mb-6">
            <button
              onClick={runAdminTests}
              disabled={loading}
              className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
                             {loading ? 'Đang kiểm tra APIs...' : 'Kiểm tra Admin APIs'}
             </button>
             
             <a
               href="/admin"
               className="bg-green-600 text-white px-6 py-2 rounded-lg hover:bg-green-700"
             >
               Đến Dashboard đầy đủ
             </a>
          </div>

          {testResults.length > 0 && (
            <div className="space-y-4">
                             <h2 className="text-xl font-semibold text-gray-900">Kết quả kiểm tra:</h2>
              
              {testResults.map((result, index) => (
                <div
                  key={index}
                  className={`p-4 rounded-lg border ${
                    result.status === 'SUCCESS' 
                      ? 'bg-green-50 border-green-200' 
                      : 'bg-red-50 border-red-200'
                  }`}
                >
                  <div className="flex justify-between items-center mb-2">
                    <h3 className="font-semibold text-gray-900">{result.name}</h3>
                    <div className="flex items-center space-x-2">
                      <span
                        className={`px-2 py-1 rounded text-sm ${
                          result.status === 'SUCCESS'
                            ? 'bg-green-100 text-green-800'
                            : 'bg-red-100 text-red-800'
                        }`}
                      >
                        {result.status}
                      </span>
                      <span className="text-sm text-gray-500">
                        Status: {result.statusCode}
                      </span>
                    </div>
                  </div>
                  
                  <div className="bg-gray-100 p-3 rounded text-sm overflow-auto max-h-32">
                    <pre>
                      {result.status === 'SUCCESS' 
                        ? JSON.stringify(result.data, null, 2)
                        : JSON.stringify(result.error, null, 2)
                      }
                    </pre>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Feature Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h3 className="text-lg font-semibold text-gray-900 mb-3">User Management</h3>
            <ul className="text-sm text-gray-600 space-y-1">
              <li>• View all users with pagination</li>
              <li>• Update user roles (Admin, User, Manager, Guest)</li>
              <li>• Change user status (Active, Pending, Inactive)</li>
              <li>• Delete users</li>
              <li>• Search and filter users</li>
            </ul>
          </div>

          <div className="bg-white p-6 rounded-lg shadow-md">
            <h3 className="text-lg font-semibold text-gray-900 mb-3">Order Management</h3>
            <ul className="text-sm text-gray-600 space-y-1">
              <li>• View all orders across system</li>
              <li>• Update order status</li>
              <li>• Track order statistics</li>
              <li>• Revenue analytics</li>
              <li>• Export order data</li>
            </ul>
          </div>

          <div className="bg-white p-6 rounded-lg shadow-md">
            <h3 className="text-lg font-semibold text-gray-900 mb-3">Product Management</h3>
            <ul className="text-sm text-gray-600 space-y-1">
              <li>• Full product catalog access</li>
              <li>• Create, edit, delete products</li>
              <li>• Manage product images</li>
              <li>• Inventory tracking</li>
              <li>• Category management</li>
            </ul>
          </div>

          <div className="bg-white p-6 rounded-lg shadow-md">
            <h3 className="text-lg font-semibold text-gray-900 mb-3">System Analytics</h3>
            <ul className="text-sm text-gray-600 space-y-1">
              <li>• User growth metrics</li>
              <li>• Revenue trends</li>
              <li>• System performance</li>
              <li>• Database health</li>
              <li>• Activity monitoring</li>
            </ul>
          </div>

          <div className="bg-white p-6 rounded-lg shadow-md">
            <h3 className="text-lg font-semibold text-gray-900 mb-3">Security Features</h3>
            <ul className="text-sm text-gray-600 space-y-1">
              <li>• JWT-based authentication</li>
              <li>• Role-based access control</li>
              <li>• Method-level security</li>
              <li>• Audit trails</li>
              <li>• Session management</li>
            </ul>
          </div>

          <div className="bg-white p-6 rounded-lg shadow-md">
            <h3 className="text-lg font-semibold text-gray-900 mb-3">System Settings</h3>
            <ul className="text-sm text-gray-600 space-y-1">
              <li>• Global configuration</li>
              <li>• Email templates</li>
              <li>• Payment settings</li>
              <li>• Notification preferences</li>
              <li>• Backup management</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdminDemo; 