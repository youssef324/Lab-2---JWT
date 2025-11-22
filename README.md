# 🔒 Lab-2 — JWT Authentication Demo

![Node.js](https://img.shields.io/badge/Node.js-18+-green?style=flat-square)
![Express](https://img.shields.io/badge/Express.js-4.x-black?style=flat-square)
![JWT](https://img.shields.io/badge/JWT-secure-yellow?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

A clean and practical demonstration of **JWT (JSON Web Token)** authentication using Node.js.  
This lab includes **two versions** of the server — one secure and one intentionally vulnerable — so you can learn both proper JWT usage and common security pitfalls.

---

## 📦 Project Structure

├── secure-server.js # Secure implementation using proper JWT verification
├── vuln-server.js # Vulnerable server (for educational attacks/testing)
├── init-db.js # Creates and seeds a SQLite 'users.db'
├── public/ # Simple front-end UI (login page + requests)
├── example.env # Template for environment variables
└── users.db # Auto-generated SQLite database

---

## 🚀 Getting Started

### 1️⃣ Clone the repository
```bash
git clone https://github.com/youssef324/Lab-2---JWT.git
cd Lab-2---JWT
