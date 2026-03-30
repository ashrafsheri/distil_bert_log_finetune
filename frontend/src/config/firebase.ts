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
const isConfigValid = Boolean(firebaseConfig.apiKey && firebaseConfig.projectId && firebaseConfig.authDomain);

const firebaseInstances = (() => {
  if (!isConfigValid) {
    return {
      app: null,
      auth: null,
      adminApp: null,
      adminAuth: null,
    };
  }

  try {
    const app = initializeApp(firebaseConfig);
    const auth = getAuth(app);
    const adminApp = initializeApp(firebaseConfig, 'ADMIN_APP');
    const adminAuth = getAuth(adminApp);

    return { app, auth, adminApp, adminAuth };
  } catch (error) {
    console.error('Firebase initialization failed:', error);
    return {
      app: null,
      auth: null,
      adminApp: null,
      adminAuth: null,
    };
  }
})();

// Initialize Firebase Authentication and get a reference to the service
// Note: auth may be null if initialization failed
export const auth = firebaseInstances.auth;
export const adminAuth = firebaseInstances.adminAuth;
export default firebaseInstances.app;
