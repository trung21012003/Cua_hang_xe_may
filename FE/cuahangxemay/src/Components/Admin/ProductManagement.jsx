import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Package, Search, Filter, Plus, Edit, Eye, Trash2, X, Upload, 
  Settings, PieChart, BarChart3, TrendingUp, AlertTriangle,
  Motorcycle, Palette, Layers, Wrench, ChevronDown, ChevronRight,
  Info, Tag, DollarSign, Truck, Calendar, Users
} from 'lucide-react';

const ProductManagement = () => {
  // States
  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedProduct, setSelectedProduct] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [modalMode, setModalMode] = useState('view'); // view, edit, add
  const [expandedSpecs, setExpandedSpecs] = useState({});
  const [activeTab, setActiveTab] = useState('overview');
  
  // Filters
  const [filters, setFilters] = useState({
    search: '',
    brand: 'all',
    status: 'all',
    priceRange: 'all',
    inStock: 'all'
  });

  // Product form state
  const [productForm, setProductForm] = useState({
    // Basic info
    name: '',
    description: '',
    price: '',
    avatar: '',
    
    // Technical specs
    weight: '',
    size: '',
    petrolCapacity: '',
    saddleHeight: '',
    wheelSize: '',
    beforeFork: '',
    afterFork: '',
    maxiumCapacity: '',
    oilCapacity: '',
    fuelConsumption: '',
    cylinderCapacity: '',
    maxiumMoment: '',
    compressionRatio: '',
    engieType: '',
    
    // Relations
    brandName: '',
    motolineName: '',
    
    // Versions and colors (will be handled separately)
    versions: [],
    totalStock: 0,
    status: 'ACTIVE'
  });

  // Fetch products
  const fetchProducts = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('jwtToken');
      const response = await axios.get('http://localhost:8080/api/products/manage', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setProducts(response.data || []);
    } catch (error) {
      console.error('Error fetching products:', error);
      alert('Lỗi khi tải danh sách sản phẩm');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProducts();
  }, []);

  // Filter products
  const filteredProducts = products.filter(product => {
    const matchesSearch = product.name?.toLowerCase().includes(filters.search.toLowerCase()) ||
                         product.description?.toLowerCase().includes(filters.search.toLowerCase());
    const matchesBrand = filters.brand === 'all' || product.brandName === filters.brand;
    const matchesStatus = filters.status === 'all' || product.status === filters.status;
    
    return matchesSearch && matchesBrand && matchesStatus;
  });

  // Get unique brands
  const brands = [...new Set(products.map(p => p.brandName).filter(Boolean))];

  // Handle product actions
  const handleView = (product) => {
    setSelectedProduct(product);
    setModalMode('view');
    setShowModal(true);
  };

  const handleEdit = (product) => {
    setSelectedProduct(product);
    setProductForm({
      ...product,
      versions: product.versionColors || []
    });
    setModalMode('edit');
    setShowModal(true);
  };

  const handleAdd = () => {
    setSelectedProduct(null);
    setProductForm({
      name: '', description: '', price: '', avatar: '',
      weight: '', size: '', petrolCapacity: '', saddleHeight: '',
      wheelSize: '', beforeFork: '', afterFork: '', maxiumCapacity: '',
      oilCapacity: '', fuelConsumption: '', cylinderCapacity: '',
      maxiumMoment: '', compressionRatio: '', engieType: '',
      brandName: '', motolineName: '', versions: [], totalStock: 0,
      status: 'ACTIVE'
    });
    setModalMode('add');
    setShowModal(true);
  };

  const handleSave = async () => {
    try {
      const token = localStorage.getItem('jwtToken');
      const url = modalMode === 'add' 
        ? 'http://localhost:8080/api/products/manage'
        : `http://localhost:8080/api/products/manage/${selectedProduct.id}`;
      
      const method = modalMode === 'add' ? 'post' : 'put';
      
      await axios[method](url, productForm, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      alert(`${modalMode === 'add' ? 'Thêm' : 'Cập nhật'} sản phẩm thành công!`);
      setShowModal(false);
      fetchProducts();
    } catch (error) {
      console.error('Error saving product:', error);
      alert(`Lỗi khi ${modalMode === 'add' ? 'thêm' : 'cập nhật'} sản phẩm`);
    }
  };

  const handleDelete = async (productId) => {
    if (!confirm('Bạn có chắc chắn muốn xóa sản phẩm này?')) return;
    
    try {
      const token = localStorage.getItem('jwtToken');
      await axios.delete(`http://localhost:8080/api/products/admin/${productId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      alert('Xóa sản phẩm thành công!');
      fetchProducts();
    } catch (error) {
      console.error('Error deleting product:', error);
      alert('Lỗi khi xóa sản phẩm');
    }
  };

  const toggleSpecs = (productId) => {
    setExpandedSpecs(prev => ({
      ...prev,
      [productId]: !prev[productId]
    }));
  };

  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('vi-VN', {
      style: 'currency',
      currency: 'VND'
    }).format(amount || 0);
  };

  const getStockStatus = (stock) => {
    if (stock === 0) return { text: 'Hết hàng', color: 'red' };
    if (stock < 10) return { text: 'Sắp hết', color: 'yellow' };
    return { text: 'Còn hàng', color: 'green' };
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-4">
              <Package className="h-8 w-8 text-blue-600" />
              <h1 className="text-2xl font-bold text-gray-900">Quản lý sản phẩm</h1>
            </div>
            <button
              onClick={handleAdd}
              className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center space-x-2"
            >
              <Plus className="h-4 w-4" />
              <span>Thêm sản phẩm</span>
            </button>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="bg-white rounded-lg shadow-sm p-6 mb-6">
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Tìm kiếm sản phẩm..."
                value={filters.search}
                onChange={(e) => setFilters({...filters, search: e.target.value})}
                className="pl-10 w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
            
            <select
              value={filters.brand}
              onChange={(e) => setFilters({...filters, brand: e.target.value})}
              className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">Tất cả thương hiệu</option>
              {brands.map(brand => (
                <option key={brand} value={brand}>{brand}</option>
              ))}
            </select>

            <select
              value={filters.status}
              onChange={(e) => setFilters({...filters, status: e.target.value})}
              className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">Tất cả trạng thái</option>
              <option value="ACTIVE">Đang bán</option>
              <option value="INACTIVE">Ngừng bán</option>
              <option value="OUT_OF_STOCK">Hết hàng</option>
            </select>

            <select
              value={filters.priceRange}
              onChange={(e) => setFilters({...filters, priceRange: e.target.value})}
              className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">Tất cả giá</option>
              <option value="under-50">Dưới 50 triệu</option>
              <option value="50-100">50-100 triệu</option>
              <option value="above-100">Trên 100 triệu</option>
            </select>

            <div className="text-sm text-gray-600 flex items-center">
              Tổng: <span className="font-semibold ml-1">{filteredProducts.length}</span> sản phẩm
            </div>
          </div>
        </div>

        {/* Products Grid */}
        {loading ? (
          <div className="text-center py-8">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
            <p className="mt-4 text-gray-600">Đang tải...</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
            {filteredProducts.map(product => {
              const stockStatus = getStockStatus(product.totalStock || 0);
              const isExpanded = expandedSpecs[product.id];
              
              return (
                <div key={product.id} className="bg-white rounded-lg shadow-sm border overflow-hidden">
                  {/* Product Image */}
                  <div className="relative">
                    <img
                      src={product.avatar ? `http://localhost:8080/api/files/${product.avatar}` : '/api/placeholder/400/300'}
                      alt={product.name}
                      className="w-full h-48 object-cover"
                    />
                    <div className="absolute top-2 right-2">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                        stockStatus.color === 'green' ? 'bg-green-100 text-green-800' :
                        stockStatus.color === 'yellow' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-red-100 text-red-800'
                      }`}>
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
                      <span className="text-sm text-gray-500">#{product.id}</span>
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
                        <Wrench className="h-4 w-4 text-gray-400" />
                        <span>{product.engieType || 'N/A'}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Truck className="h-4 w-4 text-gray-400" />
                        <span>{product.fuelConsumption || 'N/A'}</span>
                      </div>
                    </div>

                    {/* Expanded specs */}
                    {isExpanded && (
                      <div className="mb-4 p-3 bg-gray-50 rounded-lg">
                        <div className="grid grid-cols-2 gap-2 text-sm">
                          <div><strong>Trọng lượng:</strong> {product.weight}</div>
                          <div><strong>Kích thước:</strong> {product.size}</div>
                          <div><strong>Bình xăng:</strong> {product.petrolCapacity}</div>
                          <div><strong>Chiều cao yên:</strong> {product.saddleHeight}</div>
                          <div><strong>Kích thước bánh:</strong> {product.wheelSize}</div>
                          <div><strong>Dung tích xi lanh:</strong> {product.cylinderCapacity}</div>
                        </div>
                      </div>
                    )}

                    <button
                      onClick={() => toggleSpecs(product.id)}
                      className="w-full text-center text-sm text-blue-600 hover:text-blue-700 mb-4 flex items-center justify-center space-x-1"
                    >
                      {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                      <span>{isExpanded ? 'Thu gọn' : 'Xem thông số kỹ thuật'}</span>
                    </button>

                    {/* Versions & Colors Preview */}
                    {product.versionColors && product.versionColors.length > 0 && (
                      <div className="mb-4">
                        <div className="text-sm text-gray-600 mb-2">
                          {product.versionColors.length} phiên bản
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {product.versionColors.slice(0, 3).map(version => (
                            <span key={version.id} className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs">
                              {version.versionName}
                            </span>
                          ))}
                          {product.versionColors.length > 3 && (
                            <span className="text-xs text-gray-500">+{product.versionColors.length - 3} khác</span>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Actions */}
                    <div className="flex items-center justify-between">
                      <div className="flex space-x-2">
                        <button
                          onClick={() => handleView(product)}
                          className="p-2 text-gray-600 hover:text-blue-600 hover:bg-blue-50 rounded"
                          title="Xem chi tiết"
                        >
                          <Eye className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleEdit(product)}
                          className="p-2 text-gray-600 hover:text-yellow-600 hover:bg-yellow-50 rounded"
                          title="Chỉnh sửa"
                        >
                          <Edit className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDelete(product.id)}
                          className="p-2 text-gray-600 hover:text-red-600 hover:bg-red-50 rounded"
                          title="Xóa"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                      
                      <div className="text-right text-sm">
                        <div className="text-gray-500">Tồn kho</div>
                        <div className="font-medium">{product.totalStock || 0}</div>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {filteredProducts.length === 0 && !loading && (
          <div className="text-center py-12">
            <Package className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <p className="text-xl text-gray-600 mb-2">Không tìm thấy sản phẩm nào</p>
            <p className="text-gray-500">Thử thay đổi bộ lọc hoặc thêm sản phẩm mới</p>
          </div>
        )}
      </div>

      {/* Product Modal */}
      {showModal && (
        <ProductModal
          product={selectedProduct}
          productForm={productForm}
          setProductForm={setProductForm}
          mode={modalMode}
          onClose={() => setShowModal(false)}
          onSave={handleSave}
          formatCurrency={formatCurrency}
        />
      )}
    </div>
  );
};

// Product Modal Component
const ProductModal = ({ product, productForm, setProductForm, mode, onClose, onSave, formatCurrency }) => {
  const [activeTab, setActiveTab] = useState('basic');
  
  const isReadOnly = mode === 'view';
  const title = mode === 'view' ? 'Chi tiết sản phẩm' : 
                mode === 'edit' ? 'Chỉnh sửa sản phẩm' : 'Thêm sản phẩm mới';

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg w-full max-w-4xl max-h-[90vh] overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between p-6 border-b">
          <h2 className="text-xl font-semibold">{title}</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <X className="h-6 w-6" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto">
          {/* Tabs */}
          <div className="border-b">
            <nav className="flex space-x-8 px-6">
              {[
                { id: 'basic', name: 'Thông tin cơ bản', icon: Info },
                { id: 'specs', name: 'Thông số kỹ thuật', icon: Settings },
                { id: 'versions', name: 'Phiên bản & Màu sắc', icon: Palette },
                { id: 'inventory', name: 'Kho hàng', icon: Package }
              ].map(tab => {
                const Icon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`py-4 px-1 border-b-2 font-medium text-sm flex items-center space-x-2 ${
                      activeTab === tab.id
                        ? 'border-blue-500 text-blue-600'
                        : 'border-transparent text-gray-500 hover:text-gray-700'
                    }`}
                  >
                    <Icon className="h-4 w-4" />
                    <span>{tab.name}</span>
                  </button>
                );
              })}
            </nav>
          </div>

          {/* Tab Content */}
          <div className="p-6">
            {activeTab === 'basic' && (
              <BasicInfoTab 
                productForm={productForm} 
                setProductForm={setProductForm} 
                isReadOnly={isReadOnly}
                formatCurrency={formatCurrency}
              />
            )}
            
            {activeTab === 'specs' && (
              <SpecsTab 
                productForm={productForm} 
                setProductForm={setProductForm} 
                isReadOnly={isReadOnly}
              />
            )}
            
            {activeTab === 'versions' && (
              <VersionsTab 
                product={product}
                isReadOnly={isReadOnly}
                formatCurrency={formatCurrency}
              />
            )}
            
            {activeTab === 'inventory' && (
              <InventoryTab 
                product={product}
                isReadOnly={isReadOnly}
              />
            )}
          </div>
        </div>

        {/* Modal Footer */}
        {!isReadOnly && (
          <div className="flex items-center justify-end space-x-4 p-6 border-t bg-gray-50">
            <button
              onClick={onClose}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Hủy
            </button>
            <button
              onClick={onSave}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              {mode === 'add' ? 'Thêm sản phẩm' : 'Lưu thay đổi'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

// Tab Components
const BasicInfoTab = ({ productForm, setProductForm, isReadOnly, formatCurrency }) => (
  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">Tên sản phẩm</label>
        <input
          type="text"
          value={productForm.name}
          onChange={(e) => setProductForm({...productForm, name: e.target.value})}
          disabled={isReadOnly}
          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-50"
        />
      </div>
      
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">Mô tả</label>
        <textarea
          value={productForm.description}
          onChange={(e) => setProductForm({...productForm, description: e.target.value})}
          disabled={isReadOnly}
          rows={4}
          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-50"
        />
      </div>
      
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">Giá (VND)</label>
        <input
          type="number"
          value={productForm.price}
          onChange={(e) => setProductForm({...productForm, price: e.target.value})}
          disabled={isReadOnly}
          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-50"
        />
        {productForm.price && (
          <p className="text-sm text-gray-600 mt-1">
            {formatCurrency(productForm.price)}
          </p>
        )}
      </div>
    </div>
    
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">Thương hiệu</label>
        <input
          type="text"
          value={productForm.brandName}
          onChange={(e) => setProductForm({...productForm, brandName: e.target.value})}
          disabled={isReadOnly}
          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-50"
        />
      </div>
      
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">Dòng xe</label>
        <input
          type="text"
          value={productForm.motolineName}
          onChange={(e) => setProductForm({...productForm, motolineName: e.target.value})}
          disabled={isReadOnly}
          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-50"
        />
      </div>
      
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">Trạng thái</label>
        <select
          value={productForm.status}
          onChange={(e) => setProductForm({...productForm, status: e.target.value})}
          disabled={isReadOnly}
          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-50"
        >
          <option value="ACTIVE">Đang bán</option>
          <option value="INACTIVE">Ngừng bán</option>
          <option value="OUT_OF_STOCK">Hết hàng</option>
        </select>
      </div>
      
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">Hình ảnh</label>
        <input
          type="text"
          value={productForm.avatar}
          onChange={(e) => setProductForm({...productForm, avatar: e.target.value})}
          disabled={isReadOnly}
          placeholder="URL hình ảnh"
          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-50"
        />
      </div>
    </div>
  </div>
);

const SpecsTab = ({ productForm, setProductForm, isReadOnly }) => {
  const specs = [
    { key: 'weight', label: 'Trọng lượng', unit: 'kg' },
    { key: 'size', label: 'Kích thước', unit: 'mm' },
    { key: 'petrolCapacity', label: 'Dung tích bình xăng', unit: 'lít' },
    { key: 'saddleHeight', label: 'Chiều cao yên', unit: 'mm' },
    { key: 'wheelSize', label: 'Kích thước bánh xe', unit: 'inch' },
    { key: 'beforeFork', label: 'Phuộc trước', unit: '' },
    { key: 'afterFork', label: 'Phuộc sau', unit: '' },
    { key: 'maxiumCapacity', label: 'Tải trọng tối đa', unit: 'kg' },
    { key: 'oilCapacity', label: 'Dung tích dầu máy', unit: 'lít' },
    { key: 'fuelConsumption', label: 'Mức tiêu thụ nhiên liệu', unit: 'l/100km' },
    { key: 'cylinderCapacity', label: 'Dung tích xi lanh', unit: 'cc' },
    { key: 'maxiumMoment', label: 'Mômen xoắn tối đa', unit: 'Nm' },
    { key: 'compressionRatio', label: 'Tỷ số nén', unit: '' },
    { key: 'engieType', label: 'Loại động cơ', unit: '' }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      {specs.map(spec => (
        <div key={spec.key}>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            {spec.label} {spec.unit && `(${spec.unit})`}
          </label>
          <input
            type="text"
            value={productForm[spec.key] || ''}
            onChange={(e) => setProductForm({...productForm, [spec.key]: e.target.value})}
            disabled={isReadOnly}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-50"
          />
        </div>
      ))}
    </div>
  );
};

const VersionsTab = ({ product, isReadOnly, formatCurrency }) => {
  if (!product?.versionColors || product.versionColors.length === 0) {
    return (
      <div className="text-center py-8">
        <Layers className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <p className="text-gray-600">Chưa có phiên bản nào</p>
        {!isReadOnly && (
          <button className="mt-4 bg-blue-600 text-white px-4 py-2 rounded-lg">
            Thêm phiên bản
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {product.versionColors.map(version => (
        <div key={version.id} className="border rounded-lg p-4">
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-lg font-semibold">{version.versionName}</h4>
            <span className="text-lg font-bold text-blue-600">
              {formatCurrency(version.price)}
            </span>
          </div>
          
          {version.colors && version.colors.length > 0 && (
            <div>
              <h5 className="text-sm font-medium text-gray-700 mb-3">Màu sắc có sẵn:</h5>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {version.colors.map(color => (
                  <div key={color.id} className="flex items-center space-x-3 p-3 bg-gray-50 rounded-lg">
                    <div 
                      className="w-6 h-6 rounded-full border border-gray-300"
                      style={{ backgroundColor: color.value || '#ccc' }}
                    ></div>
                    <div className="flex-1">
                      <div className="font-medium">{color.color}</div>
                      <div className="text-sm text-gray-600">
                        {formatCurrency(color.price)} • Tồn: {color.quantity || 0}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

const InventoryTab = ({ product, isReadOnly }) => {
  const totalStock = product?.versionColors?.reduce((total, version) => {
    return total + (version.colors?.reduce((sum, color) => sum + (color.quantity || 0), 0) || 0);
  }, 0) || 0;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-blue-50 p-4 rounded-lg">
          <div className="text-2xl font-bold text-blue-600">{totalStock}</div>
          <div className="text-sm text-blue-800">Tổng tồn kho</div>
        </div>
        <div className="bg-green-50 p-4 rounded-lg">
          <div className="text-2xl font-bold text-green-600">
            {product?.versionColors?.length || 0}
          </div>
          <div className="text-sm text-green-800">Phiên bản</div>
        </div>
        <div className="bg-purple-50 p-4 rounded-lg">
          <div className="text-2xl font-bold text-purple-600">
            {product?.versionColors?.reduce((total, version) => 
              total + (version.colors?.length || 0), 0) || 0}
          </div>
          <div className="text-sm text-purple-800">Màu sắc</div>
        </div>
        <div className="bg-yellow-50 p-4 rounded-lg">
          <div className="text-2xl font-bold text-yellow-600">
            {totalStock < 10 ? 'Thấp' : 'Ổn định'}
          </div>
          <div className="text-sm text-yellow-800">Trạng thái kho</div>
        </div>
      </div>

      {product?.versionColors && (
        <div className="space-y-4">
          <h4 className="text-lg font-semibold">Chi tiết tồn kho</h4>
          {product.versionColors.map(version => (
            <div key={version.id} className="border rounded-lg p-4">
              <h5 className="font-medium mb-3">{version.versionName}</h5>
              {version.colors && version.colors.length > 0 ? (
                <div className="space-y-2">
                  {version.colors.map(color => (
                    <div key={color.id} className="flex items-center justify-between py-2 border-b border-gray-100 last:border-b-0">
                      <div className="flex items-center space-x-3">
                        <div 
                          className="w-4 h-4 rounded-full border"
                          style={{ backgroundColor: color.value || '#ccc' }}
                        ></div>
                        <span>{color.color}</span>
                      </div>
                      <div className="text-right">
                        <div className="font-medium">{color.quantity || 0} cái</div>
                        <div className="text-sm text-gray-600">
                          {color.quantity === 0 ? 'Hết hàng' : 
                           color.quantity < 5 ? 'Sắp hết' : 'Còn hàng'}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-gray-500">Chưa có màu sắc nào</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default ProductManagement; 