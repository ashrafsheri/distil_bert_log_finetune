import React from 'react';
import { Link } from 'react-router-dom';

const WelcomePage: React.FC = () => {
  return (
    <div className="min-h-screen flex items-center justify-center relative overflow-hidden">
      {/* Animated background elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 left-10 w-72 h-72 bg-vt-primary/10 rounded-full blur-3xl animate-float"></div>
        <div className="absolute bottom-20 right-10 w-96 h-96 bg-vt-error/10 rounded-full blur-3xl animate-float" style={{ animationDelay: '1s' }}></div>
        <div className="absolute top-1/2 left-1/2 w-80 h-80 bg-vt-success/10 rounded-full blur-3xl animate-float" style={{ animationDelay: '2s' }}></div>
      </div>

      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 text-center relative z-10">
        {/* Hero Section */}
        <div className="space-y-12 animate-fade-in">
          {/* Logo and Title */}
          <div className="space-y-6">
            <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-vt-primary to-vt-success rounded-2xl shadow-lg shadow-vt-primary/30 mb-6 animate-pulse-glow">
              <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <h1 className="text-6xl md:text-7xl font-bold">
              <span className="gradient-text">LogGuard</span>
            </h1>
            <p className="text-2xl md:text-3xl text-vt-light/90 font-light max-w-3xl mx-auto leading-relaxed">
              Advanced Log Analysis & Real-Time Anomaly Detection
            </p>
            <p className="text-lg text-vt-muted max-w-2xl mx-auto">
              Powered by ensemble AI models combining rule-based detection, isolation forest, and transformer networks
            </p>
          </div>

          {/* Features Grid */}
          <div className="grid md:grid-cols-3 gap-8 mt-20">
            <div className="glass-strong rounded-2xl p-8 border border-vt-primary/20 card-hover group animate-slide-up stagger-1">
              <div className="w-16 h-16 bg-gradient-to-br from-vt-primary/30 to-vt-primary/10 rounded-xl flex items-center justify-center mb-6 mx-auto group-hover:scale-110 transition-transform duration-300">
                <svg className="w-8 h-8 text-vt-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
              <h3 className="text-xl font-bold text-vt-light mb-3">Real-Time Monitoring</h3>
              <p className="text-vt-muted leading-relaxed">
                Monitor system logs in real-time with instant anomaly detection and threat alerts via WebSocket connections
              </p>
            </div>

            <div className="glass-strong rounded-2xl p-8 border border-vt-success/20 card-hover group animate-slide-up stagger-2">
              <div className="w-16 h-16 bg-gradient-to-br from-vt-success/30 to-vt-success/10 rounded-xl flex items-center justify-center mb-6 mx-auto group-hover:scale-110 transition-transform duration-300">
                <svg className="w-8 h-8 text-vt-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
                </svg>
              </div>
              <h3 className="text-xl font-bold text-vt-light mb-3">Ensemble AI Models</h3>
              <p className="text-vt-muted leading-relaxed">
                Three-layer detection system: Rule-based patterns, isolation forest statistics, and transformer deep learning
              </p>
            </div>

            <div className="glass-strong rounded-2xl p-8 border border-vt-warning/20 card-hover group animate-slide-up stagger-3">
              <div className="w-16 h-16 bg-gradient-to-br from-vt-warning/30 to-vt-warning/10 rounded-xl flex items-center justify-center mb-6 mx-auto group-hover:scale-110 transition-transform duration-300">
                <svg className="w-8 h-8 text-vt-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-1.964-1.333-2.732 0L3.732 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <h3 className="text-xl font-bold text-vt-light mb-3">Intelligent Alerts</h3>
              <p className="text-vt-muted leading-relaxed">
                Configurable thresholds with detailed threat analysis showing individual model scores and ensemble decisions
              </p>
            </div>
          </div>

          {/* Stats Banner */}
          <div className="glass rounded-2xl p-6 border border-vt-muted/20 animate-slide-up stagger-4">
            <div className="grid grid-cols-3 gap-8">
              <div className="text-center">
                <div className="text-3xl md:text-4xl font-bold gradient-text mb-2">3</div>
                <div className="text-sm text-vt-muted uppercase tracking-wide">AI Models</div>
              </div>
              <div className="text-center border-x border-vt-muted/20">
                <div className="text-3xl md:text-4xl font-bold gradient-text mb-2">99.9%</div>
                <div className="text-sm text-vt-muted uppercase tracking-wide">Accuracy</div>
              </div>
              <div className="text-center">
                <div className="text-3xl md:text-4xl font-bold gradient-text mb-2">&lt;10ms</div>
                <div className="text-sm text-vt-muted uppercase tracking-wide">Response Time</div>
              </div>
            </div>
          </div>

          {/* CTA Button */}
          <div className="pt-8">
            <Link
              to="/login"
              className="group inline-flex items-center px-10 py-5 bg-gradient-to-r from-vt-primary to-vt-success text-white font-bold rounded-2xl hover:shadow-2xl hover:shadow-vt-primary/40 transition-all duration-300 transform hover:-translate-y-1 hover:scale-105"
            >
              <span className="text-lg">Get Started</span>
              <svg className="ml-3 w-6 h-6 group-hover:translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
              </svg>
            </Link>
            <p className="text-sm text-vt-muted mt-4">
              Sign in to start monitoring your system logs instantly
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default WelcomePage;
