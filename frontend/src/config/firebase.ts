// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || "",
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || "",
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || "",
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || "",
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || "",
  appId: import.meta.env.VITE_FIREBASE_APP_ID || "",
  measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID || ""
};

// Validate that Firebase config has required values
const isConfigValid = firebaseConfig.apiKey && firebaseConfig.projectId && firebaseConfig.authDomain;

// Initialize Firebase
let app: ReturnType<typeof initializeApp> | null = null;
let auth: ReturnType<typeof getAuth> | null = null;
// Separate auth instance for user creation (admin operations)
let adminAuth: ReturnType<typeof getAuth> | null = null;
let adminApp: ReturnType<typeof initializeApp> | null = null;

try {
  if (isConfigValid) {
    // Main app for user login
    app = initializeApp(firebaseConfig);
    auth = getAuth(app);
    
    // Admin app for creating users without switching sessions
    adminApp = initializeApp(firebaseConfig, 'ADMIN_APP');
    adminAuth = getAuth(adminApp);
  }
} catch (error) {
  // Firebase initialization error - silently fail
}

// Initialize Firebase Authentication and get a reference to the service
// Note: auth may be null if initialization failed
export { auth, adminAuth };
export default app;
