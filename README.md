# RustAuth

A simple authentication microservice built with Rust, Axum, and PostgreSQL, featuring JWT-based authentication and a minimal HTML frontend for testing.

---

## Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [Setup](#setup)
- [Environment Variables](#environment-variables)
- [Database Schema](#database-schema)
- [API Endpoints](#api-endpoints)
- [Frontend Usage](#frontend-usage)
- [Error Handling](#error-handling)
- [Development Notes](#development-notes)

---

## Features

- User registration and login with hashed passwords
- JWT-based authentication
- Protected `/me` endpoint
- CORS support for frontend testing
- Minimal HTML frontend for manual testing

---

## Project Structure

```
RustAuth/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── routes/
│   │   └── auth.rs
│   ├── utils/
│   │   └── auth_middleware.rs
│   └── models/
├── frontend/
│   └── index.html
└── .env
```

---

## Setup

1. **Clone the repository**
2. **Install dependencies**
   ```sh
   cargo build
   ```
3. **Set up your PostgreSQL database**
   - Create a database and a `users` table (see [Database Schema](#database-schema))
4. **Configure environment variables** in a `.env` file:
   ```
   DATABASE_URL=postgres://<user>:<password>@localhost:5432/<database>
   PRIVATE_KEY=your_jwt_secret_key
   ```
5. **Run the backend**
   ```sh
   cargo run
   ```
6. **Open the frontend**
   - Open `frontend/index.html` in your browser.

---

## Environment Variables

- `DATABASE_URL`: PostgreSQL connection string.
- `PRIVATE_KEY`: Secret key for signing JWTs.

See [example_env.md](./example_env.md) for a sample `.env` file and instructions on generating a private key.
---

## Database Schema

You need a `users` table:

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);
```

---

## API Endpoints

### `POST /register`

Register a new user.

- **Request Body:**
  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```
- **Responses:**
  - `201 Created`: Success
  - `409 Conflict`: Username already exists
  - `500 Internal Server Error`: Other errors

---

### `POST /login`

Authenticate a user and receive a JWT.

- **Request Body:**
  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```
- **Responses:**
  - `200 OK`: `{ "token": "<jwt>" }`
  - `401 Unauthorized`: Invalid credentials

---

### `GET /me`

Get the current user's info (protected).

- **Headers:**
  - `Authorization: Bearer <jwt>`
- **Responses:**
  - `200 OK`: `Hello, <username>!`
  - `401 Unauthorized`: Invalid or missing token

---

## Frontend Usage

- Open `frontend/index.html` in your browser.
- Register a new user, log in, and test the `/me` endpoint.
- The frontend stores the JWT in memory and uses it for authenticated requests.

---

## Error Handling

- All endpoints return appropriate HTTP status codes and error messages.
- Custom error types are used for both route handlers and middleware.
- CORS errors are handled via the `tower-http` CORS middleware.

---

## Development Notes

- Uses Axum 0.7.x and tower-http 0.6.x for middleware.
- Passwords are hashed before storage.
- JWTs are signed with the secret key from `PRIVATE_KEY`.
- The project is suitable for learning and prototyping, not for production use without further security hardening.

---

## License

MIT 
