# 前端登录跳转问题 - 完整解决方案

## 问题描述

用户在前端登录页面输入用户名密码后点击登录，后端API返回成功，但页面无法跳转到Dashboard，一直停留在登录页面或跳转回登录页面。

## 根本原因分析

### 问题1: 环境变量配置错误 ❌

**症状**：前端请求到错误的API地址

**原因**：`.env` 文件中配置了错误的API URL
```bash
# .env
VITE_API_BASE_URL=http://localhost:3000  # ❌ 错误
```

但Web Dashboard实际运行在端口9000，导致前端axios请求到`http://localhost:3000/api/v1/*`而不是`http://localhost:9000/api/v1/*`。

**解决方案**：
```bash
# .env
VITE_API_BASE_URL=  # ✅ 空字符串，使用相对路径
```

**验证方法**：
```bash
# 检查.env文件
cat services/web_dashboard/.env

# 检查构建后的baseURL
grep -o "baseURL[^,}]*" services/web_dashboard/dist/assets/*.js
```

### 问题2: Axios拦截器闭包陷阱 ❌

**症状**：登录API成功（200 OK），但`/api/v1/auth/me`请求没有发出或token未传递

**原因**：axios拦截器在apiClient创建时设置，此时localStorage中还没有token。当后续调用`apiClient.get('/auth/me')`时，拦截器读取的还是初始化时的空token。

**错误代码**：
```typescript
// api.ts
const apiClient = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
})

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')  // 闭包陷阱
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// AuthContext.tsx
const authToken = await api.auth.login(credentials)
// token已存储到localStorage
setToken(authToken.access_token)

const response = await apiClient.get('/auth/me')  // ❌ 拦截器可能读取不到token
```

**解决方案**：使用原生`fetch`并直接传递token
```typescript
const accessToken = authToken.access_token

// 直接fetch，明确传递Authorization header
const response = await fetch(`${window.location.origin}/api/v1/auth/me`, {
  headers: {
    'Authorization': `Bearer ${accessToken}`,
  },
})
```

### 问题3: React状态更新时序 ❌

**症状**：登录成功但立即跳转导致`isAuthenticated`仍为false

**原因**：
```typescript
await login({ username, password })
navigate('/')  // 立即导航，但setUser()可能还未完成状态更新
```

**解决方案**：
```typescript
await login({ username, password })
// 使用setTimeout确保React状态更新后再导航
setTimeout(() => navigate('/'), 0)
```

## 完整修复代码

### 1. 修复 .env 文件

```bash
# services/web_dashboard/.env
VITE_API_BASE_URL=  # 空字符串，使用相对路径
```

### 2. 修复 AuthContext.tsx

```typescript
/**
 * Login function
 */
const login = useCallback(async (credentials: LoginCredentials) => {
  setIsLoading(true)
  try {
    const authToken = await api.auth.login(credentials)
    const accessToken = authToken.access_token

    // Store token
    setToken(accessToken)

    // Fetch user info using native fetch with explicit token
    const response = await fetch(`${window.location.origin}/api/v1/auth/me`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
    })

    if (!response.ok) {
      throw new Error('Failed to fetch user information')
    }

    const result = await response.json()
    if (!result.success || !result.data) {
      throw new Error(result.error || 'Failed to fetch user information')
    }

    const userData = result.data
    const userSession: AuthUser = {
      id: userData.id,
      username: userData.username,
      email: userData.email,
      role: userData.role,
      permissions: userData.permissions || [],
    }

    setUser(userSession)
    console.log('Login successful, user:', userSession)
  } catch (error) {
    console.error('Login failed:', error)
    setToken(null)
    setUser(null)
    throw error
  } finally {
    setIsLoading(false)
  }
}, [])

/**
 * Initialize auth state from localStorage
 */
useEffect(() => {
  const initAuth = async () => {
    const storedToken = localStorage.getItem('access_token')
    if (storedToken) {
      setToken(storedToken)

      try {
        // Use native fetch with explicit token
        const response = await fetch(`${window.location.origin}/api/v1/auth/me`, {
          headers: {
            'Authorization': `Bearer ${storedToken}`,
          },
        })

        if (response.ok) {
          const result = await response.json()
          if (result.success && result.data) {
            const userData = result.data
            const userSession: AuthUser = {
              id: userData.id,
              username: userData.username,
              email: userData.email,
              role: userData.role,
              permissions: userData.permissions || [],
            }
            setUser(userSession)
          }
        }
      } catch (error) {
        console.error('Failed to fetch user info:', error)
        setToken(null)
        localStorage.removeItem('access_token')
      }
    }
    setIsLoading(false)
  }

  initAuth()
}, [])
```

### 3. 修复 Login.tsx

```typescript
const handleSubmit = async (e: React.FormEvent) => {
  e.preventDefault()
  setError('')

  try {
    await login({ username, password })
    // Use setTimeout to ensure React state updates before navigation
    setTimeout(() => navigate('/'), 0)
  } catch (err) {
    console.error('Login error:', err)
    setError('Invalid username or password')
  }
}
```

## 调试步骤

### 1. 检查环境变量
```bash
cat services/web_dashboard/.env
# 确认 VITE_API_BASE_URL= 为空
```

### 2. 验证后端API
```bash
# 测试登录
curl -X POST http://localhost:9000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# 测试获取用户信息
TOKEN=<从上面的响应获取>
curl -X GET http://localhost:9000/api/v1/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

### 3. 监控日志
```bash
tail -f logs/web_dashboard.log | grep -E "login|auth|POST|GET"
```

### 4. 清除浏览器缓存
- Mac: `Cmd+Shift+R`
- Windows: `Ctrl+F5`
- 或手动清除浏览器缓存

## 构建和部署

### 开发环境
```bash
# 1. 修改代码后重新构建
cd services/web_dashboard
npx vite build

# 2. 重启服务
cd /Users/newmba/security
./scripts/services.sh restart web_dashboard
```

### 生产环境
```bash
# 确保构建前清理缓存
rm -rf dist/ node_modules/.vite .vite

# 使用生产环境变量
cp .env.production .env

# 构建
npx vite build
```

## 关键经验总结

### ✅ 必做事项

1. **环境变量配置**
   - `.env` 中的 `VITE_API_BASE_URL` 必须为空字符串（使用相对路径）
   - 或确保指向正确的后端地址

2. **Token传递**
   - 使用原生 `fetch` 而不是 axios 拦截器
   - 明确传递 `Authorization: Bearer ${token}` header

3. **状态更新时序**
   - 登录成功后使用 `setTimeout(..., 0)` 确保React状态更新
   - 让`setUser()`完成后再执行`navigate()`

### ❌ 避免的错误

1. **不要在构建后修改.env文件而不重新构建**
   - Vite在构建时读取环境变量
   - 修改后必须重新构建

2. **不要依赖axios拦截器读取动态token**
   - 拦截器在apiClient创建时设置闭包
   - localStorage中后续设置的值可能读取不到

3. **不要在异步操作后立即导航**
   - React状态更新是异步的
   - 使用setTimeout或await状态更新后再导航

## 快速诊断清单

| 症状 | 检查项 | 解决方案 |
|------|--------|----------|
| 无法登录 | 检查`.env`文件中的`VITE_API_BASE_URL` | 设为空字符串 |
| 登录成功但跳转失败 | 检查浏览器console是否有错误 | 查看Network标签是否请求/auth/me |
| /auth/me返回401 | 检查Authorization header | 使用fetch明确传递token |
| 一直显示loading | 检查`isLoading`状态 | 确保finally块执行 |

## 验证方法

### 完整测试流程
```bash
# 1. 构建前端
cd services/web_dashboard
npx vite build

# 2. 重启服务
cd /Users/newmba/security
./scripts/services.sh restart web_dashboard

# 3. 测试API
curl -X POST http://localhost:9000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# 4. 访问页面
open http://localhost:9000
```

### 登录凭据
- Username: `admin`
- Password: `admin123`

---

**最后更新**: 2026-02-10
**问题状态**: ✅ 已解决
**关键修复**:
1. `.env` 文件配置
2. 使用原生fetch替代axios拦截器
3. React状态更新时序控制
