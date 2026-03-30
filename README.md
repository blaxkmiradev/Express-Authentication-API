# Express Authentication API

A production-ready JWT authentication REST API built with Express.js and SQLite (via sql.js).

## Features

- ✅ Register / Login / Logout
- ✅ JWT Access Tokens (15m) + Refresh Tokens (7d)
- ✅ Refresh token rotation (new tokens on each refresh)
- ✅ Logout from all devices
- ✅ Change password (invalidates all sessions)
- ✅ Role-based access control (`user`, `moderator`, `admin`)
- ✅ Admin user management (list, role change, deactivate, delete)
- ✅ Input validation with descriptive errors
- ✅ Rate limiting (10 req/15min on auth routes)
- ✅ Security headers via Helmet
- ✅ CORS support
- ✅ SQLite persistence (file-based via sql.js)

---

## Quick Start

```bash
# Install dependencies
npm install

# Start server (uses .env for config)
npm start

# Dev mode (auto-restart on file changes — Node 18+)
npm run dev
```

Server starts at: `http://localhost:3000`

---

## Environment Variables (`.env`)

```env
PORT=3000
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_REFRESH_SECRET=your-super-secret-refresh-key-change-in-production
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d
NODE_ENV=development
```

---

## API Endpoints

### Auth Routes

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/auth/register` | No | Register new user |
| `POST` | `/auth/login` | No | Login with email + password |
| `POST` | `/auth/refresh` | No | Refresh access token |
| `POST` | `/auth/logout` | ✅ | Logout (revoke refresh token) |
| `POST` | `/auth/logout-all` | ✅ | Logout all devices |
| `GET`  | `/auth/me` | ✅ | Get current user profile |
| `PUT`  | `/auth/change-password` | ✅ | Change password |

### User Routes (Admin)

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| `GET`    | `/users` | Admin | List all users (paginated) |
| `GET`    | `/users/:id` | Admin / Self | Get user by ID |
| `PUT`    | `/users/:id/role` | Admin | Update user role |
| `PUT`    | `/users/:id/status` | Admin | Activate/deactivate user |
| `DELETE` | `/users/:id` | Admin | Delete user |

---

## Request / Response Examples

### Register

```http
POST /auth/register
Content-Type: application/json

{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "SecurePass1"
}
```

```json
{
  "message": "Registration successful",
  "user": {
    "id": "uuid",
    "username": "johndoe",
    "email": "john@example.com",
    "role": "user"
  },
  "tokens": {
    "accessToken": "eyJ...",
    "refreshToken": "eyJ..."
  }
}
```

### Login

```http
POST /auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "SecurePass1"
}
```

### Using a Protected Route

```http
GET /auth/me
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Refresh Tokens

```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJ..."
}
```

---

## Password Requirements

- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number

---

## Project Structure

```
auth-api/
├── index.js              # App entry point
├── .env                  # Environment config
├── data/
│   └── auth.db           # SQLite database (auto-created)
└── src/
    ├── database.js        # SQLite setup & helpers
    ├── middleware/
    │   ├── auth.js        # JWT authenticate + authorize
    │   └── validate.js    # Input validation
    └── routes/
        ├── auth.js        # Auth endpoints
        └── users.js       # User management (admin)
```

---

## Database Schema

### `users`
| Column | Type | Description |
|--------|------|-------------|
| id | TEXT PK | UUID |
| username | TEXT UNIQUE | lowercase |
| email | TEXT UNIQUE | lowercase |
| password_hash | TEXT | bcrypt (cost 12) |
| role | TEXT | user / moderator / admin |
| is_active | INTEGER | 1 = active, 0 = disabled |
| created_at | TEXT | ISO datetime |
| updated_at | TEXT | ISO datetime |

### `refresh_tokens`
| Column | Type | Description |
|--------|------|-------------|
| id | TEXT PK | UUID |
| user_id | TEXT FK | References users.id |
| token | TEXT UNIQUE | JWT refresh token |
| expires_at | TEXT | Expiry datetime |
| created_at | TEXT | ISO datetime |
