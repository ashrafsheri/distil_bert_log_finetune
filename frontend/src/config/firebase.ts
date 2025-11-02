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

// Debug: Log environment variable status (only in development)
if (import.meta.env.DEV) {
  console.log('Firebase Config Status:', {
    hasApiKey: !!firebaseConfig.apiKey,
    hasProjectId: !!firebaseConfig.projectId,
    hasAuthDomain: !!firebaseConfig.authDomain,
    envVarsFound: {
      VITE_FIREBASE_API_KEY: !!import.meta.env.VITE_FIREBASE_API_KEY,
      VITE_FIREBASE_PROJECT_ID: !!import.meta.env.VITE_FIREBASE_PROJECT_ID,
      VITE_FIREBASE_AUTH_DOMAIN: !!import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
    }
  });
}

// Validate that Firebase config has required values
const isConfigValid = firebaseConfig.apiKey && firebaseConfig.projectId && firebaseConfig.authDomain;

if (!isConfigValid) {
  console.error('Firebase configuration is missing required values:', {
    apiKey: firebaseConfig.apiKey ? '✓' : '✗ Missing',
    projectId: firebaseConfig.projectId ? '✓' : '✗ Missing',
    authDomain: firebaseConfig.authDomain ? '✓' : '✗ Missing',
  });
  console.error('Please create a .env file in the frontend directory with your Firebase configuration.');
  console.error('Required variables: VITE_FIREBASE_API_KEY, VITE_FIREBASE_PROJECT_ID, VITE_FIREBASE_AUTH_DOMAIN');
}

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
    
    console.log('Firebase initialized successfully');
    console.log('Admin auth instance created for user management');
  } else {
    console.error('Firebase configuration is incomplete. Cannot initialize.');
    console.error('Auth features will be disabled until configuration is provided.');
  }
} catch (error) {
  console.error('Error initializing Firebase:', error);
}

// Initialize Firebase Authentication and get a reference to the service
// Note: auth may be null if initialization failed
export { auth, adminAuth };
export default app;
