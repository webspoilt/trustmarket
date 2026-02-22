# 🛡️ TrustMarket

TrustMarket is India's safest and most trusted Peer-to-Peer (P2P) marketplace. It features AI-powered trust scoring, mandatory video verification for sellers, quantum-resistant Argon2id encryption for user security, behavioral bot-detection, and a sleek, modern glassmorphic UI.

## 🚀 Features
- **Quantum-Resistant Security**: Password hashing with Argon2id and anomaly/bot detection.
- **Video Verification**: Sellers must provide a video to establish authenticity.
- **AI Trust Engine**: Calculates trust scores based on user behavior and history.
- **Glassmorphic UI**: Beautiful, interactive 3D elements and modern styling.
- **Real-Time Bidding & Chat**: End-to-end integrated messaging and offers.
- **Capacitor Mobile Support**: Web app seamlessly compiles to Android & iOS.

---

## 💻 Tech Stack
- **Frontend**: React (v18), Tailwind CSS 3, Three.js (React Three Fiber), Zustand.
- **Backend**: Node.js, Express.js, MongoDB (Mongoose), Socket.IO.
- **Security**: Argon2id, JWT, Shannon Entropy analysis, Euclidean Distance anomalies.
- **Mobile Packaging**: Ionic Capacitor.

---

## 🛠️ Local Development Setup

### Prerequisites
- Node.js (v18+)
- MongoDB connection string (Local or MongoDB Atlas)
- Cloudinary account credentials (for handling media uploads)

### 1. Clone & Install
```bash
git clone https://github.com/webspoilt/trustmarket.git
cd trustmarket

# Install Backend Dependencies
cd server
npm install

# Install Frontend Dependencies
cd ../client
npm install
```

### 2. Environment Variables
You need to set up `.env` files in both the `server` and `client` directories.

**`server/.env`:**
```ini
PORT=5000
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_super_secret_jwt_key
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret
FRONTEND_URL=http://localhost:3000
GOOGLE_CLIENT_ID=your_google_oauth_client_id
```

**`client/.env`:**
```ini
REACT_APP_API_URL=http://localhost:5000/api
REACT_APP_GOOGLE_CLIENT_ID=your_google_oauth_client_id
```

### 3. Run the Application
Open two separate terminal windows.

**Backend:**
```bash
cd server
npm run dev
```

**Frontend:**
```bash
cd client
npm start
```

---

## 🌍 Deployment Guide (Vercel + Render)

Because TrustMarket uses **WebSockets (Socket.IO)** for real-time chat, the backend cannot be fully hosted on Vercel (as Vercel is strictly Serverless and severs sustained socket connections). 

The optimal, free-tier friendly deployment strategy is:
- **Frontend** → Vercel
- **Backend** → Render / Railway

### Step 1: Deploy Backend to Render (or Railway)
1. Go to [Render](https://render.com/) and click **New > Web Service**.
2. Connect this GitHub repository.
3. Configure the following settings:
   - **Root Directory**: `server`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
4. Add all the environment variables from your `server/.env`.
5. Deploy! Once finished, Render will give you a URL (e.g., `https://trustmarket-api.onrender.com`).

### Step 2: Deploy Frontend to Vercel
1. Go to [Vercel](https://vercel.com/) and click **Add New > Project**.
2. Import this GitHub repository.
3. Configure the **Build and Output Settings**:
   - **Root Directory**: Select `client` (Click edit and type this).
   - **Framework Preset**: Create React App
   - **Build Command**: `npm run build`
4. **Environment Variables**:
   - Add `REACT_APP_API_URL` and set its value to your new Render Backend URL (e.g., `https://trustmarket-api.onrender.com/api`).
5. Click **Deploy**. Vercel will automatically detect the `.npmrc` file we created and bypass the strict peer-dependency checks perfectly.

### Step 3: Mobile Apps (Capacitor)
If you want to build the Android APK:
```bash
cd client
npm run build
npx cap sync android
npx cap open android
```
From Android Studio, click **Build > Build Bundle(s) / APK(s) > Build APK(s)**.

---
**Maintained by the TrustMarket Team.**