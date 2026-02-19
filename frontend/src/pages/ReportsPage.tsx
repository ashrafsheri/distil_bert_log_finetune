import React, { useState } from 'react';
import { auth } from '../config/firebase';
import LoadingSpinner from '../components/LoadingSpinner';
import Button from '../components/Button';
import Card from '../components/Card';

const ReportsPage: React.FC = () => {
  const [startDate, setStartDate] = useState('');
  const [startTime, setStartTime] = useState('00:00');
  const [endDate, setEndDate] = useState('');
  const [endTime, setEndTime] = useState('23:59');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Set default dates (last 7 days)
  React.useEffect(() => {
    const end = new Date();
    const start = new Date();
    start.setDate(start.getDate() - 7);

    setEndDate(end.toISOString().split('T')[0]);
    setStartDate(start.toISOString().split('T')[0]);
  }, []);

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    try {
      // Validate dates
      if (!startDate || !endDate) {
        setError('Please select both start and end dates');
        return;
      }

      // Combine date and time
      const startDateTime = `${startDate}T${startTime}:00`;
      const endDateTime = `${endDate}T${endTime}:59`;

      const start = new Date(startDateTime);
      const end = new Date(endDateTime);

      // Validate time range
      if (end <= start) {
        setError('End date/time must be after start date/time');
        return;
      }

      // Check 30-day limit
      const diffDays = (end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24);
      if (diffDays > 30) {
        setError('Time range cannot exceed 30 days');
        return;
      }

      setLoading(true);

      // Get Firebase token
      if (!auth) {
        setError('Authentication service unavailable.');
        setLoading(false);
        return;
      }
      const currentUser = auth.currentUser;
      if (!currentUser) {
        setError('Authentication required. Please log in.');
        setLoading(false);
        return;
      }
      const token = await currentUser.getIdToken();

      // Call API to generate report
      const response = await fetch('/api/v1/logs/generate-report', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          start_time: start.toISOString(),
          end_time: end.toISOString()
        })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Failed to generate report' }));
        throw new Error(errorData.detail || 'Failed to generate report');
      }

      // Get blob from response
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
      link.download = `security_report_${timestamp}.pdf`;
      
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      setSuccess('Report generated and downloaded successfully!');
    } catch (err: any) {
      const errorMsg = err.response?.data?.detail || err.message || 'Failed to generate report';
      setError(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  const handleQuickSelect = (days: number) => {
    const end = new Date();
    const start = new Date();
    start.setDate(start.getDate() - days);

    setEndDate(end.toISOString().split('T')[0]);
    setStartDate(start.toISOString().split('T')[0]);
    setStartTime('00:00');
    setEndTime('23:59');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      <div className="max-w-4xl mx-auto px-6 py-8">
        <div className="mb-10">
          <h1 className="text-4xl font-bold text-white mb-3">Security Reports</h1>
          <p className="text-slate-400 text-lg">Generate comprehensive PDF reports of security analytics</p>
        </div>

        <Card className="p-8">
          <form onSubmit={handleGenerateReport}>
            <div className="space-y-6">
              {/* Quick Select Buttons */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-3">
                  Quick Select
                </label>
                <div className="flex flex-wrap gap-3">
                  <Button
                    type="button"
                    onClick={() => handleQuickSelect(1)}
                    variant="secondary"
                    size="sm"
                  >
                    Last 24 Hours
                  </Button>
                  <Button
                    type="button"
                    onClick={() => handleQuickSelect(7)}
                    variant="secondary"
                    size="sm"
                  >
                    Last 7 Days
                  </Button>
                  <Button
                    type="button"
                    onClick={() => handleQuickSelect(30)}
                    variant="secondary"
                    size="sm"
                  >
                    Last 30 Days
                  </Button>
                </div>
              </div>

              {/* Start Date/Time */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Start Date
                  </label>
                  <input
                    type="date"
                    value={startDate}
                    onChange={(e) => setStartDate(e.target.value)}
                    className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-vt-primary"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Start Time
                  </label>
                  <input
                    type="time"
                    value={startTime}
                    onChange={(e) => setStartTime(e.target.value)}
                    className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-vt-primary"
                    required
                  />
                </div>
              </div>

              {/* End Date/Time */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    End Date
                  </label>
                  <input
                    type="date"
                    value={endDate}
                    onChange={(e) => setEndDate(e.target.value)}
                    className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-vt-primary"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    End Time
                  </label>
                  <input
                    type="time"
                    value={endTime}
                    onChange={(e) => setEndTime(e.target.value)}
                    className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-vt-primary"
                    required
                  />
                </div>
              </div>

              {/* Info message */}
              <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                <div className="flex items-start gap-3">
                  <svg className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <div>
                    <p className="text-sm text-blue-300">
                      The report will include statistics on malicious packets, unique malicious IPs, 
                      email alerts, timeline charts, and detailed analysis of each flagged IP address.
                    </p>
                    <p className="text-xs text-blue-400 mt-2">
                      Maximum time range: 30 days
                    </p>
                  </div>
                </div>
              </div>

              {/* Error message */}
              {error && (
                <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
                  <div className="flex items-center gap-3">
                    <svg className="w-5 h-5 text-red-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <p className="text-sm text-red-300">{error}</p>
                  </div>
                </div>
              )}

              {/* Success message */}
              {success && (
                <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                  <div className="flex items-center gap-3">
                    <svg className="w-5 h-5 text-green-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    <p className="text-sm text-green-300">{success}</p>
                  </div>
                </div>
              )}

              {/* Submit button */}
              <div className="pt-4">
                <Button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-vt-primary hover:bg-vt-primary/80 px-6 py-4 text-lg font-semibold"
                >
                  {loading ? (
                    <div className="flex items-center justify-center gap-3">
                      <LoadingSpinner />
                      <span>Generating Report...</span>
                    </div>
                  ) : (
                    <div className="flex items-center justify-center gap-2">
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                      <span>Generate PDF Report</span>
                    </div>
                  )}
                </Button>
              </div>
            </div>
          </form>
        </Card>

        {/* Report Features */}
        <Card className="mt-6 p-6 bg-slate-800/50">
          <h3 className="text-lg font-semibold text-white mb-4">Report Includes:</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex items-start gap-3">
              <svg className="w-5 h-5 text-vt-primary mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
              <div>
                <p className="text-sm font-medium text-white">Statistics Overview</p>
                <p className="text-xs text-slate-400">Total logs, malicious packets, threat percentage</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <svg className="w-5 h-5 text-vt-primary mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
              </svg>
              <div>
                <p className="text-sm font-medium text-white">Attack Timeline</p>
                <p className="text-xs text-slate-400">Visual chart of attacks over time</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <svg className="w-5 h-5 text-vt-primary mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              <div>
                <p className="text-sm font-medium text-white">Malicious IP Analysis</p>
                <p className="text-xs text-slate-400">Detailed breakdown with detection methods</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <svg className="w-5 h-5 text-vt-primary mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
              <div>
                <p className="text-sm font-medium text-white">Alert Summary</p>
                <p className="text-xs text-slate-400">Email alerts and notification count</p>
              </div>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
};

export default ReportsPage;
