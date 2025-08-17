import React, { useState, useEffect } from 'react';
import { User, Settings, LogOut, Shield, Smartphone, Eye, Edit3, Unlink, Plus, Search, Filter, MoreHorizontal, Trash2, Power, PowerOff } from 'lucide-react';

// Конфигурация API
const API_CONFIG = {
  BASE_URL: 'https://6puu14cjdi.execute-api.ap-northeast-2.amazonaws.com/dev',
  SOUND_API_URL: 'https://frontend-api-prod.wethmfactory.com',
  COGNITO_CONFIG: {
    USER_POOL_ID: 'ap-northeast-2_Mh01NUKlM',
    CLIENT_ID: '3sqbfermevq30ntj0empplkd6a',
    REGION: 'ap-northeast-2'
  }
};

// Хранилище токена в памяти (вместо localStorage)
let authToken = null;
let currentUserData = null;

// API сервисы с нативным fetch
const apiService = {
  // Утилита для выполнения запросов
  async request(endpoint, options = {}) {
    const url = `${API_CONFIG.BASE_URL}${endpoint}`;
    const config = {
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...(authToken && { 'Authorization': `Bearer ${authToken}` }),
        ...options.headers
      },
      ...options
    };

    if (config.body && typeof config.body === 'object') {
      config.body = JSON.stringify(config.body);
    }

    try {
      console.log('Making API request to:', url, 'with config:', config);
      const response = await fetch(url, config);
      
      console.log('API response status:', response.status);
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        console.error('API error response:', errorData);
        throw {
          status: response.status,
          message: errorData.message || `HTTP ${response.status}`,
          response: { status: response.status, data: errorData }
        };
      }

      const data = await response.json();
      console.log('API response data:', data);
      return data;
    } catch (error) {
      console.error('API request failed:', error);
      if (error.status) {
        throw error;
      }
      throw {
        message: 'Network error. Please check your connection.',
        code: 'NETWORK_ERROR'
      };
    }
  },

  // Проверка валидности токена
  isTokenValid() {
    if (!currentUserData || !currentUserData.tokenInfo) {
      return false;
    }
    
    const { expiryDate } = currentUserData.tokenInfo;
    const now = new Date();
    
    // Проверяем, не истек ли токен (с запасом в 5 минут)
    return expiryDate && new Date(expiryDate) > new Date(now.getTime() + 5 * 60 * 1000);
  },

  // Обновление токена
  async refreshAccessToken() {
    if (!currentUserData || !currentUserData.tokenInfo || !currentUserData.tokenInfo.refreshToken) {
      throw new Error('No refresh token available');
    }

    try {
      const response = await this.request('/auth/refresh', {
        method: 'POST',
        body: { 
          refreshToken: currentUserData.tokenInfo.refreshToken 
        }
      });

      if (response.data && response.data.accessToken) {
        // Обновляем токены
        authToken = response.data.accessToken;
        currentUserData.tokenInfo = {
          ...currentUserData.tokenInfo,
          accessToken: response.data.accessToken,
          expiryDate: new Date(response.data.expiryDate)
        };
        
        console.log('Token refreshed successfully');
        return currentUserData;
      }
      
      throw new Error('Invalid refresh response');
    } catch (error) {
      console.error('Token refresh failed:', error);
      // Если обновление токена не удалось, очищаем данные пользователя
      authToken = null;
      currentUserData = null;
      throw error;
    }
  },

  // Проверка аутентификации с автоматическим обновлением токена
  async ensureAuthenticated() {
    if (!currentUserData) {
      throw { code: 'NotAuthenticated', message: 'No authenticated user' };
    }

    if (!this.isTokenValid()) {
      console.log('Token expired, attempting to refresh...');
      try {
        await this.refreshAccessToken();
      } catch (error) {
        console.error('Failed to refresh token:', error);
        throw { code: 'TokenExpired', message: 'Session expired. Please sign in again.' };
      }
    }

    return currentUserData;
  },

  // Аутентификация через AWS Cognito
  async signIn(email, password) {
    try {
      console.log('Attempting to sign in with:', email);
      
      const response = await this.request('/auth/login', {
        method: 'POST',
        body: { email, password }
      });
      
      console.log('Auth response:', response);
      
      // Обрабатываем ответ от AWS Cognito
      if (response.data && response.data.accessToken) {
        const { accessToken, refreshToken, username, expiryDate } = response.data;
        
        // Сохраняем токен для последующих запросов
        authToken = accessToken;
        
        // Сохраняем информацию о токене
        const tokenInfo = {
          accessToken,
          refreshToken,
          username,
          expiryDate: new Date(expiryDate)
        };
        
        // Создаем объект пользователя
        currentUserData = {
          id: username, // используем username как ID
          email: email,
          name: email.split('@')[0], // извлекаем имя из email
          role: 'user', // по умолчанию, можно получить из токена или API
          username: username,
          tokenInfo: tokenInfo
        };
        
        console.log('Authentication successful:', currentUserData);
        return currentUserData;
        
      } else if (response.accessToken) {
        // Если данные находятся в корне ответа
        authToken = response.accessToken;
        currentUserData = {
          id: response.username,
          email: email,
          name: email.split('@')[0],
          role: 'user',
          username: response.username,
          tokenInfo: response
        };
        
        return currentUserData;
      } else {
        throw new Error('Invalid response format from authentication service');
      }
      
    } catch (error) {
      console.error('Authentication failed:', error);
      
      // Проверяем, не истек ли токен
      if (error.status === 401) {
        throw { code: 'NotAuthorizedException', message: 'Invalid credentials or token expired.' };
      }
      
      // Fallback для демонстрации (можно удалить в продакшене)
      if (email === 'admin@test.com' && password === 'admin123') {
        const mockUser = { 
          id: 1, 
          email, 
          name: 'System Admin', 
          role: 'admin' 
        };
        authToken = 'mock-jwt-token';
        currentUserData = mockUser;
        return mockUser;
      } else if (email === 'manager@test.com' && password === 'manager123') {
        const mockUser = { 
          id: 2, 
          email, 
          name: 'Manager User', 
          role: 'manager' 
        };
        authToken = 'mock-jwt-token';
        currentUserData = mockUser;
        return mockUser;
      }
      
      throw { code: 'NotAuthorizedException', message: 'Incorrect email or password.' };
    }
  },

  async signUp(email, password, name) {
    try {
      const response = await this.request('/auth/signup', {
        method: 'POST',
        body: { email, password, name }
      });
      return response;
    } catch (error) {
      // Fallback для демонстрации
      return { 
        message: 'Please check your email to confirm your account',
        userSub: 'mock-user-id' 
      };
    }
  },

  async signOut() {
    try {
      if (authToken) {
        await this.request('/auth/signout', {
          method: 'POST'
        });
      }
    } catch (error) {
      console.warn('Sign out error:', error);
    } finally {
      authToken = null;
      currentUserData = null;
    }
  },

  async getCurrentUser() {
    try {
      return await this.ensureAuthenticated();
    } catch (error) {
      throw { code: 'NotAuthenticated', message: 'No authenticated user' };
    }
  },

  // Проверка доступности API
  async checkApiHealth() {
    const endpoints = ['/', '/health', '/status', '/users', '/devices'];
    const results = {};
    
    for (const endpoint of endpoints) {
      try {
        console.log(`Checking endpoint: ${endpoint}`);
        await this.request(endpoint, { method: 'GET' });
        results[endpoint] = 'OK';
      } catch (error) {
        results[endpoint] = `Error: ${error.status || error.message}`;
      }
    }
    
    console.log('API Health Check Results:', results);
    return results;
  },

  // Пользователи
  async getUsers() {
    console.log('Fetching users from API...');
    await this.ensureAuthenticated(); // Проверяем токен перед запросом
    return await this.request('/users');
  },

  async createUser(userData) {
    await this.ensureAuthenticated();
    return await this.request('/users', {
      method: 'POST',
      body: userData
    });
  },

  async updateUser(userId, userData) {
    await this.ensureAuthenticated();
    return await this.request(`/users/${userId}`, {
      method: 'PUT',
      body: userData
    });
  },

  async deleteUser(userId) {
    await this.ensureAuthenticated();
    return await this.request(`/users/${userId}`, {
      method: 'DELETE'
    });
  },

  // Устройства
  async getDevices() {
    console.log('Fetching devices from API...');
    await this.ensureAuthenticated(); // Проверяем токен перед запросом
    return await this.request('/devices');
  },

  async createDevice(deviceData) {
    await this.ensureAuthenticated();
    return await this.request('/devices', {
      method: 'POST',
      body: deviceData
    });
  },

  async updateDevice(deviceId, deviceData) {
    await this.ensureAuthenticated();
    return await this.request(`/devices/${deviceId}`, {
      method: 'PUT',
      body: deviceData
    });
  },

  async deleteDevice(deviceId) {
    await this.ensureAuthenticated();
    return await this.request(`/devices/${deviceId}`, {
      method: 'DELETE'
    });
  },

  async disconnectDevice(deviceId) {
    await this.ensureAuthenticated();
    return await this.request(`/devices/${deviceId}/disconnect`, {
      method: 'PUT'
    });
  }
};

// Функция обработки ошибок API
const handleApiError = (error) => {
  if (error.response) {
    const { status, data } = error.response;
    switch (status) {
      case 401:
        return 'Session expired. Please sign in again.';
      case 403:
        return 'You do not have permission to perform this action.';
      case 404:
        return 'Resource not found.';
      case 500:
        return 'Internal server error. Please try again later.';
      default:
        return data?.message || 'An error occurred. Please try again.';
    }
  } else if (error.code) {
    switch (error.code) {
      case 'UserNotConfirmedException':
        return 'Please confirm your account before signing in.';
      case 'NotAuthorizedException':
        return 'Incorrect email or password.';
      case 'UserNotFoundException':
        return 'User not found.';
      case 'TokenExpired':
      case 'NotAuthenticated':
        return 'Session expired. Please sign in again.';
      case 'NETWORK_ERROR':
        return 'Network error. Please check your connection.';
      default:
        return error.message || 'An error occurred. Please try again.';
    }
  }
  return error.message || 'Unknown error occurred.';
};

// Компонент формы аутентификации
const AuthForm = ({ onAuth }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({ email: '', password: '', name: '' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async () => {
    if (!formData.email || !formData.password) return;
    
    setLoading(true);
    setError('');

    try {
      if (isLogin) {
        const user = await apiService.signIn(formData.email, formData.password);
        onAuth(user);
      } else {
        await apiService.signUp(formData.email, formData.password, formData.name);
        setError('Please check your email to confirm your account, then sign in.');
        setIsLogin(true);
      }
    } catch (err) {
      setError(handleApiError(err));
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleSubmit();
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-xl p-8 w-full max-w-md">
        <div className="text-center mb-8">
          <div className="bg-orange-100 rounded-full w-16 h-16 flex items-center justify-center mx-auto mb-4">
            <Shield className="text-orange-600" size={32} />
          </div>
          <h1 className="text-2xl font-bold text-gray-900">Admin Console</h1>
          <p className="text-gray-600 mt-2">{isLogin ? 'Sign in to your account' : 'Create new account'}</p>
        </div>

        <div className="space-y-6">
          {!isLogin && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Name</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({...formData, name: e.target.value})}
                onKeyPress={handleKeyPress}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent"
              />
            </div>
          )}
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Email</label>
            <input
              type="email"
              value={formData.email}
              onChange={(e) => setFormData({...formData, email: e.target.value})}
              onKeyPress={handleKeyPress}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Password</label>
            <input
              type="password"
              value={formData.password}
              onChange={(e) => setFormData({...formData, password: e.target.value})}
              onKeyPress={handleKeyPress}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent"
            />
          </div>

          {error && (
            <div className={`border px-4 py-3 rounded-lg text-sm ${
              error.includes('confirm') 
                ? 'bg-blue-50 border-blue-200 text-blue-600'
                : 'bg-red-50 border-red-200 text-red-600'
            }`}>
              {error}
            </div>
          )}

          <button
            onClick={handleSubmit}
            disabled={loading}
            className="w-full bg-orange-600 text-white py-2 px-4 rounded-lg hover:bg-orange-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? 'Loading...' : (isLogin ? 'Sign In' : 'Create Account')}
          </button>
        </div>

        <div className="mt-6 text-center">
          <button
            onClick={() => setIsLogin(!isLogin)}
            className="text-orange-600 hover:text-orange-800 text-sm"
          >
            {isLogin ? "Don't have an account? Sign up" : 'Already have an account? Sign in'}
          </button>
        </div>

        <div className="mt-6 p-4 bg-gray-50 rounded-lg text-xs text-gray-600">
          <p className="font-medium mb-2">Test Accounts:</p>
          <p>Admin: admin@test.com / admin123</p>
          <p>Manager: manager@test.com / manager123</p>
        </div>
      </div>
    </div>
  );
};

// AWS-Style Table Component
const DataTable = ({ 
  columns, 
  data, 
  onRowSelect, 
  onRowAction, 
  selectedRows = [], 
  actions = [],
  searchPlaceholder = "Search...",
  loading = false
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [sortColumn, setSortColumn] = useState('');
  const [sortDirection, setSortDirection] = useState('asc');

  const filteredData = data.filter(item => 
    Object.values(item).some(value => 
      String(value).toLowerCase().includes(searchTerm.toLowerCase())
    )
  );

  const sortedData = [...filteredData].sort((a, b) => {
    if (!sortColumn) return 0;
    const aValue = a[sortColumn];
    const bValue = b[sortColumn];
    if (aValue < bValue) return sortDirection === 'asc' ? -1 : 1;
    if (aValue > bValue) return sortDirection === 'asc' ? 1 : -1;
    return 0;
  });

  const handleSort = (column) => {
    if (sortColumn === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(column);
      setSortDirection('asc');
    }
  };

  if (loading) {
    return (
      <div className="bg-white rounded-lg border border-gray-200 p-8">
        <div className="flex items-center justify-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-600"></div>
          <span className="ml-2 text-gray-600">Loading...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg border border-gray-200">
      {/* Table Header */}
      <div className="px-6 py-4 border-b border-gray-200">
        <div className="flex justify-between items-center">
          <div className="flex items-center space-x-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={16} />
              <input
                type="text"
                placeholder={searchPlaceholder}
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-9 pr-4 py-2 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-orange-500 focus:border-transparent"
              />
            </div>
            <button className="flex items-center space-x-2 px-3 py-2 text-sm border border-gray-300 rounded-md hover:bg-gray-50">
              <Filter size={16} />
              <span>Filter</span>
            </button>
          </div>
          <div className="flex items-center space-x-2">
            {actions.map((action, index) => (
              <button
                key={index}
                onClick={action.onClick}
                className={`px-3 py-2 text-sm rounded-md transition-colors flex items-center space-x-1 ${
                  action.variant === 'primary' 
                    ? 'bg-orange-600 text-white hover:bg-orange-700' 
                    : 'border border-gray-300 text-gray-700 hover:bg-gray-50'
                }`}
              >
                {action.icon && <action.icon size={16} />}
                <span>{action.label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              {onRowSelect && (
                <th className="w-4 px-6 py-3 text-left">
                  <input type="checkbox" className="rounded border-gray-300" />
                </th>
              )}
              {columns.map((column) => (
                <th 
                  key={column.key}
                  className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                  onClick={() => column.sortable && handleSort(column.key)}
                >
                  <div className="flex items-center space-x-1">
                    <span>{column.label}</span>
                    {column.sortable && sortColumn === column.key && (
                      <span className="text-orange-600">
                        {sortDirection === 'asc' ? '↑' : '↓'}
                      </span>
                    )}
                  </div>
                </th>
              ))}
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {sortedData.map((row, index) => (
              <tr key={row.id || index} className="hover:bg-gray-50">
                {onRowSelect && (
                  <td className="px-6 py-4">
                    <input 
                      type="checkbox" 
                      className="rounded border-gray-300"
                      checked={selectedRows.includes(row.id)}
                      onChange={() => onRowSelect(row.id)}
                    />
                  </td>
                )}
                {columns.map((column) => (
                  <td key={column.key} className="px-6 py-4 whitespace-nowrap text-sm">
                    {column.render ? column.render(row[column.key], row) : row[column.key]}
                  </td>
                ))}
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm">
                  <button 
                    onClick={() => onRowAction && onRowAction(row)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    <MoreHorizontal size={16} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Table Footer */}
      <div className="px-6 py-3 border-t border-gray-200 text-sm text-gray-500">
        Showing {sortedData.length} of {data.length} items
      </div>
    </div>
  );
};

// Users Management Component с API интеграцией
const UsersManagement = ({ currentUser }) => {
  const [users, setUsers] = useState([]);
  const [selectedUsers, setSelectedUsers] = useState([]);
  const [editingUser, setEditingUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState('');

  // Загрузка пользователей при монтировании компонента
  useEffect(() => {
    loadUsers();
  }, []);

  const loadUsers = async () => {
    try {
      setLoading(true);
      setApiError('');
      const usersData = await apiService.getUsers();
      setUsers(usersData);
    } catch (error) {
      const errorMessage = handleApiError(error);
      setApiError(errorMessage);
      
      // Если токен истек, перенаправляем на страницу входа
      if (error.code === 'TokenExpired' || error.code === 'NotAuthenticated') {
        // Можно добавить обратный вызов для выхода из системы
        console.log('Token expired, should redirect to login');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSaveUser = async () => {
    try {
      setLoading(true);
      await apiService.updateUser(editingUser.id, editingUser);
      setUsers(users.map(u => u.id === editingUser.id ? editingUser : u));
      setEditingUser(null);
    } catch (error) {
      setApiError(handleApiError(error));
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const renderUserName = (value, row) => {
    return (
      <div className="flex items-center">
        <div className="bg-gray-100 rounded-full w-8 h-8 flex items-center justify-center mr-3">
          <User size={16} className="text-gray-600" />
        </div>
        <div>
          <div className="font-medium text-gray-900">{value}</div>
          <div className="text-gray-500 text-xs">{row.email}</div>
        </div>
      </div>
    );
  };

  const renderRole = (value) => {
    return (
      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
        value === 'admin' 
          ? 'bg-red-100 text-red-800' 
          : 'bg-blue-100 text-blue-800'
      }`}>
        {value}
      </span>
    );
  };

  const renderStatus = (value) => {
    return (
      <span className={`inline-flex items-center px-2 py-1 text-xs font-semibold rounded-full ${
        value === 'active' 
          ? 'bg-green-100 text-green-800' 
          : 'bg-gray-100 text-gray-800'
      }`}>
        {value === 'active' ? <Power size={12} className="mr-1" /> : <PowerOff size={12} className="mr-1" />}
        {value}
      </span>
    );
  };

  const renderDeviceCount = (value) => {
    const count = Array.isArray(value) ? value.length : value || 0;
    return <span className="text-gray-900 font-medium">{count}</span>;
  };

  const renderDate = (value) => {
    return <span className="text-gray-600">{formatDate(value)}</span>;
  };

  const userColumns = [
    {
      key: 'name',
      label: 'Name',
      sortable: true,
      render: renderUserName
    },
    {
      key: 'role',
      label: 'Role',
      sortable: true,
      render: renderRole
    },
    {
      key: 'status',
      label: 'Status',
      sortable: true,
      render: renderStatus
    },
    {
      key: 'devices',
      label: 'Devices',
      render: renderDeviceCount
    },
    {
      key: 'lastLogin',
      label: 'Last Login',
      sortable: true,
      render: renderDate
    },
    {
      key: 'createdAt',
      label: 'Created',
      sortable: true,
      render: renderDate
    }
  ];

  const handleUserAction = (user) => {
    if (currentUser.role === 'admin') {
      setEditingUser({...user});
    }
  };

  const userActions = currentUser.role === 'admin' ? [
    {
      label: 'Add User',
      icon: Plus,
      variant: 'primary',
      onClick: () => console.log('Add user')
    }
  ] : [];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Users</h2>
          <p className="text-gray-600 mt-1">Manage user accounts and permissions</p>
        </div>
      </div>

      <DataTable
        columns={userColumns}
        data={users}
        onRowSelect={currentUser.role === 'admin' ? (id) => {
          setSelectedUsers(prev => 
            prev.includes(id) 
              ? prev.filter(i => i !== id)
              : [...prev, id]
          );
        } : null}
        onRowAction={handleUserAction}
        selectedRows={selectedUsers}
        actions={userActions}
        searchPlaceholder="Search users..."
        loading={loading}
      />

      {/* Edit User Modal */}
      {editingUser && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-xl p-6 w-full max-w-md">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Edit User</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Name</label>
                <input
                  type="text"
                  value={editingUser.name}
                  onChange={(e) => setEditingUser({...editingUser, name: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Email</label>
                <input
                  type="email"
                  value={editingUser.email}
                  onChange={(e) => setEditingUser({...editingUser, email: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Role</label>
                <select
                  value={editingUser.role}
                  onChange={(e) => setEditingUser({...editingUser, role: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent"
                >
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Status</label>
                <select
                  value={editingUser.status}
                  onChange={(e) => setEditingUser({...editingUser, status: e.target.value})}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent"
                >
                  <option value="active">Active</option>
                  <option value="inactive">Inactive</option>
                </select>
              </div>
            </div>
            <div className="flex justify-end space-x-3 mt-6">
              <button
                onClick={() => setEditingUser(null)}
                className="px-4 py-2 text-gray-600 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveUser}
                disabled={loading}
                className="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 disabled:opacity-50 transition-colors"
              >
                Save Changes
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Devices Management Component
const DevicesManagement = ({ currentUser }) => {
  const [devices, setDevices] = useState([]);
  const [users, setUsers] = useState([]);
  const [selectedDevices, setSelectedDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState('');

  useEffect(() => {
    loadDevices();
    loadUsers();
  }, []);

  const loadDevices = async () => {
    try {
      setLoading(true);
      setApiError('');
      const devicesData = await apiService.getDevices();
      setDevices(devicesData);
    } catch (error) {
      setApiError(handleApiError(error));
    } finally {
      setLoading(false);
    }
  };

  const loadUsers = async () => {
    try {
      const usersData = await apiService.getUsers();
      setUsers(usersData);
    } catch (error) {
      console.warn('Failed to load users for devices view');
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getUserName = (userId) => {
    if (!userId) return 'Unassigned';
    const user = users.find(u => u.id === userId);
    return user ? user.name : 'Unknown User';
  };

  const getDeviceIcon = (type) => {
    switch (type.toLowerCase()) {
      case 'mobile':
        return <Smartphone size={16} className="text-blue-600" />;
      case 'laptop':
        return <Settings size={16} className="text-green-600" />;
      case 'tablet':
        return <Smartphone size={16} className="text-purple-600" />;
      default:
        return <Settings size={16} className="text-gray-600" />;
    }
  };

  const renderDeviceName = (value, row) => {
    return (
      <div className="flex items-center">
        <div className="bg-gray-100 rounded-full w-8 h-8 flex items-center justify-center mr-3">
          {getDeviceIcon(row.type)}
        </div>
        <div>
          <div className="font-medium text-gray-900">{value}</div>
          <div className="text-gray-500 text-xs">{row.model}</div>
        </div>
      </div>
    );
  };

  const renderAssignedUser = (value, row) => {
    return (
      <div>
        <div className="font-medium text-gray-900">{getUserName(value)}</div>
        {value && (
          <div className="text-gray-500 text-xs">
            {users.find(u => u.id === value)?.email}
          </div>
        )}
      </div>
    );
  };

  const renderStatus = (value) => {
    return (
      <span className={`inline-flex items-center px-2 py-1 text-xs font-semibold rounded-full ${
        value === 'connected' 
          ? 'bg-green-100 text-green-800' 
          : 'bg-red-100 text-red-800'
      }`}>
        {value === 'connected' ? <Power size={12} className="mr-1" /> : <PowerOff size={12} className="mr-1" />}
        {value}
      </span>
    );
  };

  const renderIP = (value) => {
    return <span className="font-mono text-sm text-gray-600">{value}</span>;
  };

  const renderDate = (value) => {
    return <span className="text-gray-600">{formatDate(value)}</span>;
  };

  const deviceColumns = [
    {
      key: 'name',
      label: 'Device',
      sortable: true,
      render: renderDeviceName
    },
    {
      key: 'type',
      label: 'Type',
      sortable: true,
      render: (value) => <span className="text-gray-900">{value}</span>
    },
    {
      key: 'userId',
      label: 'Assigned User',
      sortable: true,
      render: renderAssignedUser
    },
    {
      key: 'status',
      label: 'Status',
      sortable: true,
      render: renderStatus
    },
    {
      key: 'os',
      label: 'OS',
      render: (value) => <span className="text-gray-900">{value}</span>
    },
    {
      key: 'ipAddress',
      label: 'IP Address',
      render: renderIP
    },
    {
      key: 'lastSeen',
      label: 'Last Seen',
      sortable: true,
      render: renderDate
    }
  ];

  const handleDeviceAction = (device) => {
    console.log('Device action:', device);
  };

  const handleDisconnectDevice = async (deviceId) => {
    if (currentUser.role === 'admin') {
      try {
        await apiService.disconnectDevice(deviceId);
        setDevices(devices.map(d => 
          d.id === deviceId ? {...d, userId: null, status: 'disconnected'} : d
        ));
      } catch (error) {
        setApiError(handleApiError(error));
      }
    }
  };

  const deviceActions = [];
  
  if (currentUser.role === 'admin') {
    deviceActions.push({
      label: 'Add Device',
      icon: Plus,
      variant: 'primary',
      onClick: () => console.log('Add device')
    });
    
    if (selectedDevices.length > 0) {
      deviceActions.push({
        label: 'Disconnect Selected',
        icon: Unlink,
        onClick: async () => {
          for (const id of selectedDevices) {
            await handleDisconnectDevice(id);
          }
          setSelectedDevices([]);
        }
      });
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Devices</h2>
          <p className="text-gray-600 mt-1">Monitor and manage connected devices</p>
        </div>
      </div>

      {apiError && (
        <div className="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-lg">
          {apiError}
          <button 
            onClick={loadDevices}
            className="ml-2 underline hover:no-underline"
          >
            Retry
          </button>
        </div>
      )}

      <DataTable
        columns={deviceColumns}
        data={devices}
        onRowSelect={currentUser.role === 'admin' ? (id) => {
          setSelectedDevices(prev => 
            prev.includes(id) 
              ? prev.filter(i => i !== id)
              : [...prev, id]
          );
        } : null}
        onRowAction={handleDeviceAction}
        selectedRows={selectedDevices}
        actions={deviceActions}
        searchPlaceholder="Search devices..."
        loading={loading}
      />
    </div>
  );
};

// Main App Component
const AdminPanel = () => {
  const [currentUser, setCurrentUser] = useState(null);
  const [activeTab, setActiveTab] = useState('users');
  const [loading, setLoading] = useState(false);

  // Проверка аутентификации при загрузке
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const user = await apiService.getCurrentUser();
        setCurrentUser(user);
      } catch (error) {
        // Пользователь не аутентифицирован
      }
    };
    checkAuth();
  }, []);

  const handleAuth = (user) => {
    setCurrentUser(user);
  };

  const handleSignOut = async () => {
    setLoading(true);
    try {
      await apiService.signOut();
      setCurrentUser(null);
    } catch (error) {
      console.error('Sign out error:', error);
    } finally {
      setLoading(false);
    }
  };

  if (!currentUser) {
    return <AuthForm onAuth={handleAuth} />;
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-4">
              <div className="bg-orange-600 rounded-lg w-8 h-8 flex items-center justify-center">
                <Shield className="text-white" size={20} />
              </div>
              <h1 className="text-xl font-semibold text-gray-900">Admin Console</h1>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <p className="text-sm font-medium text-gray-900">{currentUser.name}</p>
                <p className="text-xs text-gray-600 capitalize">{currentUser.role}</p>
              </div>
              <button
                onClick={handleSignOut}
                disabled={loading}
                className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors disabled:opacity-50"
                title="Sign Out"
              >
                <LogOut size={18} />
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8">
            <button
              onClick={() => setActiveTab('users')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'users'
                  ? 'border-orange-500 text-orange-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              Users
            </button>
            <button
              onClick={() => setActiveTab('devices')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'devices'
                  ? 'border-orange-500 text-orange-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              Devices
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'users' && <UsersManagement currentUser={currentUser} />}
        {activeTab === 'devices' && <DevicesManagement currentUser={currentUser} />}
      </main>
    </div>
  );
};

export default AdminPanel;