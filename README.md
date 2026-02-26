# IMDB Identity Service

A simple identity/auth microservice for an IMDB-style application.

## Getting Started

```bash
npm install
npm run dev
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/login` | User authentication |
| GET | `/api/users/search` | Search users |
| GET | `/api/admin/users/:id` | Get user by ID |
| POST | `/api/encrypt` | Encrypt data |
| POST | `/api/password-reset` | Request password reset |
| POST | `/api/upload` | Upload file |
| POST | `/api/fetch-url` | Fetch remote URL |

## Project Structure

```
imdb-identity/
  src/
    app.ts       — Express API with routes
    auth.ts      — Authentication module
    admin.ts     — Admin operations
  package.json
  tsconfig.json
```

## Tech Stack

- **Runtime**: Node.js 18+
- **Framework**: Express 4.x
- **Database**: PostgreSQL (pg)
- **Language**: TypeScript 5.x
