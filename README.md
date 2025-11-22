# 🔒 Lab-2 --- JWT Authentication Demo

![Node.js](https://img.shields.io/badge/Node.js-18+-green?style=flat-square)
![Express](https://img.shields.io/badge/Express.js-4.x-black?style=flat-square)
![JWT](https://img.shields.io/badge/JWT-secure-yellow?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

A clean and practical demonstration of **JWT (JSON Web Token)**
authentication using Node.js.\
This lab includes **two versions** of the server --- one secure and one
intentionally vulnerable --- so you can learn both proper JWT usage and
common security pitfalls.

------------------------------------------------------------------------

## 📦 Project Structure

    ├── secure-server.js      # Secure implementation using proper JWT verification
    ├── vuln-server.js        # Vulnerable server (for educational attacks/testing)
    ├── init-db.js            # Creates and seeds a SQLite 'users.db'
    ├── public/               # Simple front-end UI (login page + requests)
    ├── example.env           # Template for environment variables
    └── users.db              # Auto-generated SQLite database

------------------------------------------------------------------------

## 🚀 Getting Started

### 1️⃣ Clone the repository

``` bash
git clone https://github.com/youssef324/Lab-2---JWT.git
cd Lab-2---JWT
```

### 2️⃣ Install dependencies

``` bash
npm install
```

### 3️⃣ Set up environment variables

Copy the example environment file:

``` bash
cp example.env .env
```

Fill in the required fields inside `.env`:

    JWT_SECRET=yourStrongSecretKey
    PORT=3000

### 4️⃣ Initialize the database

``` bash
node init-db.js
```

This will generate a `users.db` file and create test users.

### 5️⃣ Start the servers

#### ✔️ Secure Server

``` bash
node secure-server.js
```

#### ⚠️ Vulnerable Server (for lab testing)

``` bash
node vuln-server.js
```

### 6️⃣ Try It Out

Open any file from the `public/` folder in your browser.

From there, you can: - Log in\
- Receive a JWT\
- Hit protected routes\
- Compare secure vs insecure behavior

------------------------------------------------------------------------

## 🔐 Features

-   ✔️ Login system using JWT\
-   ✔️ Route protection with token validation\
-   ✔️ Secure token verification (HS256)\
-   ✔️ Vulnerable version for testing JWT attacks\
-   ✔️ SQLite mini-database to store users\
-   ✔️ Clear, beginner-friendly code

------------------------------------------------------------------------

## ⚠️ Security Notes

This project is **strictly for educational & testing purposes**.

The `vuln-server.js` intentionally contains flaws to help you
understand: - Missing signature validation\
- Algorithm confusion attacks\
- Weak secrets\
- Token tampering\
- Bad authentication hygiene

Never deploy the vulnerable server. It exists so you can break it.

------------------------------------------------------------------------

## 📚 Recommended Learning Resources

-   JWT official docs\
-   Best practices for handling authentication tokens\
-   Common JWT vulnerabilities & how to avoid them\
-   Role-based authorization using JWT

------------------------------------------------------------------------
