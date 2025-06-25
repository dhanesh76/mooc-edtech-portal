
```markdown
# Mooc EdTech Backend – Authentication Service

This is the **Authentication Module** for the Mooc EdTech platform.  
It is built using **Spring Boot** and backed by **MongoDB** as the primary database.  
This repository is a work-in-progress and currently focuses on core authentication features.

---

## ✅ Features Implemented (So Far)

- **User Signup** (with email & username)
- **User Signin** (with password verification)
- **Email Verification via OTP**
- **Password Reset via OTP**
- **OTP verification system with expiry logic**
- **Short-lived JWT token for password reset**
- **Basic Exception Handling and Response Messaging**

---

## ⚙️ Tech Stack

- **Java 17**
- **Spring Boot**
- **Spring Security**
- **MongoDB** (via Spring Data Mongo)
- **JWT (JSON Web Tokens)**
- **Lombok**
- **Maven**

---

## 📂 Project Structure (Important Modules Only)

```

src/main/java/com/dhanesh/auth/portal
├── controller          # REST endpoints (signup, signin, OTP, etc.)
├── dto                 # Data transfer objects for requests/responses
├── entity              # MongoDB document model (e.g., Users)
├── service             # Business logic layer
├── security            # JWT services and filter
├── exception           # Custom exception handlers
├── model               # OTP-related helper models
├── config              # Spring Security & application configuration

```

---

## 🔐 Authentication Flow (High-Level)

1. **Signup**  
   → Stores user in DB (unverified)  
   → Sends email OTP for verification

2. **Signin**  
   → Only works if user is verified  
   → Generates JWT for session

3. **Forgot Password**  
   → Sends OTP  
   → On OTP verification, a short-lived JWT is issued  
   → This token is required to access `/reset-password`

4. **Password Reset**  
   → Only allowed with valid OTP token  
   → Enforced by verifying `otp_verified` and `token_type` claims

---

## 🔧 Environment Setup

1. **MongoDB Connection** – set your credentials in `application.properties`:
```

spring.data.mongodb.uri=mongodb+srv://<username>:<password>@<cluster-url>/auth\_db

```

2. **JWT Configuration**:
```

jwt.secret=\<your\_base64\_encoded\_secret>
jwt.expiration=86400000

```

---

## 📬 API Endpoints (Authentication Module)

| Method | Endpoint            | Description                     |
|--------|---------------------|---------------------------------|
| POST   | `/api/auth/signup`  | Register a new user             |
| POST   | `/api/auth/signin`  | Authenticate with email/pass    |
| POST   | `/api/auth/request-otp` | Request OTP for reset/verify |
| POST   | `/api/auth/verify-otp`  | Validate received OTP         |
| POST   | `/api/auth/reset-password` | Reset password with OTP token |

> ✅ All endpoints are tested using **Postman**

---

## 🚧 Roadmap

This repository will eventually support:
- Course Enrollment APIs
- Instructor/Admin Dashboards
- Payment Integration
- Progress Tracking
- Full User Role & Permission Systems

---

## 📌 Contribution

This project is actively maintained by [@dhanesh76](https://github.com/dhanesh76)  
Frontend collaboration is welcome for integrating with these APIs.

---

## 🧪 Testing

Use Postman to test all endpoints.  
Some requests (e.g., reset-password) require a valid `Bearer Token` in the header.

---

## 📄 License

MIT License. You are free to use and extend this module with attribution.

