import React from 'react';
import { Link } from 'react-router-dom';

const WelcomePage: React.FC = () => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-vt-dark via-vt-blue to-vt-dark">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        {/* Hero Section */}
        <div className="space-y-8 animate-fade-in">
          {/* Logo and Title */}
          <div className="space-y-4">
            <h1 className="text-5xl md:text-6xl font-bold text-vt-light">
              LogGuard
            </h1>
            <p className="text-xl text-vt-muted max-w-2xl mx-auto">
              Advanced log analysis and real-time anomaly detection powered by AI
            </p>
          </div>

          {/* Features Grid */}
          <div className="grid md:grid-cols-3 gap-6 mt-16">
            <div className="bg-vt-blue/50 backdrop-blur-sm rounded-xl p-6 border border-vt-muted/20">
              <div className="w-12 h-12 bg-vt-primary/20 rounded-lg flex items-center justify-center mb-4 mx-auto">
                <svg className="w-6 h-6 text-vt-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold text-vt-light mb-2">Real-time Monitoring</h3>
              <p className="text-vt-muted text-sm">Monitor logs in real-time with instant anomaly detection</p>
            </div>

            <div className="bg-vt-blue/50 backdrop-blur-sm rounded-xl p-6 border border-vt-muted/20">
              <div className="w-12 h-12 bg-vt-success/20 rounded-lg flex items-center justify-center mb-4 mx-auto">
                <svg className="w-6 h-6 text-vt-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold text-vt-light mb-2">AI-Powered Detection</h3>
              <p className="text-vt-muted text-sm">Advanced machine learning models for accurate threat detection</p>
            </div>

            <div className="bg-vt-blue/50 backdrop-blur-sm rounded-xl p-6 border border-vt-muted/20">
              <div className="w-12 h-12 bg-vt-warning/20 rounded-lg flex items-center justify-center mb-4 mx-auto">
                <svg className="w-6 h-6 text-vt-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold text-vt-light mb-2">Instant Alerts</h3>
              <p className="text-vt-muted text-sm">Get notified immediately when threats are detected</p>
            </div>
          </div>

          {/* CTA Button */}
          <div className="pt-8">
            <Link
              to="/dashboard"
              className="inline-flex items-center px-8 py-4 bg-vt-primary text-vt-dark font-semibold rounded-xl hover:bg-vt-primary/90 transition-all duration-200 shadow-vt-lg hover:shadow-vt transform hover:-translate-y-1"
            >
              <span>View Dashboard</span>
              <svg className="ml-2 w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
              </svg>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default WelcomePage;
