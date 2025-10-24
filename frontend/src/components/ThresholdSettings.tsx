import React, { useState, useEffect } from 'react';

interface ThresholdSettingsProps {
  onUpdate?: (thresholds: ThresholdValues) => void;
}

export interface ThresholdValues {
  ensemble: number;
  transformer: number;
  isolationForest: number;
  ruleBasedWeight: number;
  isoForestWeight: number;
  transformerWeight: number;
}

const ThresholdSettings: React.FC<ThresholdSettingsProps> = ({ onUpdate }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [thresholds, setThresholds] = useState<ThresholdValues>({
    ensemble: 0.5,
    transformer: 6.5,
    isolationForest: 0.5,
    ruleBasedWeight: 0.3,
    isoForestWeight: 0.6,
    transformerWeight: 0.7,
  });

  const [tempThresholds, setTempThresholds] = useState<ThresholdValues>(thresholds);

  useEffect(() => {
    // Load thresholds from localStorage if available
    const saved = localStorage.getItem('anomaly_thresholds');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        setThresholds(parsed);
        setTempThresholds(parsed);
      } catch (e) {
        console.error('Failed to load thresholds from localStorage', e);
      }
    }
  }, []);

  const handleSliderChange = (key: keyof ThresholdValues, value: number) => {
    setTempThresholds(prev => ({ ...prev, [key]: value }));
  };

  const handleApply = () => {
    setThresholds(tempThresholds);
    localStorage.setItem('anomaly_thresholds', JSON.stringify(tempThresholds));
    if (onUpdate) {
      onUpdate(tempThresholds);
    }
    setIsOpen(false);
  };

  const handleReset = () => {
    const defaultThresholds: ThresholdValues = {
      ensemble: 0.5,
      transformer: 6.5,
      isolationForest: 0.5,
      ruleBasedWeight: 0.3,
      isoForestWeight: 0.6,
      transformerWeight: 0.7,
    };
    setTempThresholds(defaultThresholds);
  };

  return (
    <div className="relative">
      {/* Settings Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-4 py-2 bg-vt-blue/50 hover:bg-vt-blue/70 rounded-lg border border-vt-muted/20 transition-all text-vt-light"
      >
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
        <span className="text-sm font-medium">Threshold Settings</span>
      </button>

      {/* Settings Panel */}
      {isOpen && (
        <div className="absolute right-0 mt-2 w-96 bg-vt-blue/90 backdrop-blur-sm rounded-xl border border-vt-muted/20 shadow-xl z-50 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-vt-light">Detection Thresholds</h3>
            <button
              onClick={() => setIsOpen(false)}
              className="text-vt-muted hover:text-vt-light transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          <div className="space-y-6">
            {/* Ensemble Threshold */}
            <div>
              <div className="flex justify-between items-center mb-2">
                <label className="text-sm font-medium text-vt-muted">Ensemble Threshold</label>
                <span className="text-sm font-mono text-vt-light">{tempThresholds.ensemble.toFixed(2)}</span>
              </div>
              <input
                type="range"
                min="0"
                max="1"
                step="0.01"
                value={tempThresholds.ensemble}
                onChange={(e) => handleSliderChange('ensemble', parseFloat(e.target.value))}
                className="w-full h-2 bg-vt-muted/20 rounded-lg appearance-none cursor-pointer slider"
              />
              <p className="text-xs text-vt-muted mt-1">Final score threshold for anomaly detection</p>
            </div>

            {/* Transformer Threshold */}
            <div>
              <div className="flex justify-between items-center mb-2">
                <label className="text-sm font-medium text-vt-muted">Transformer NLL Threshold</label>
                <span className="text-sm font-mono text-vt-light">{tempThresholds.transformer.toFixed(2)}</span>
              </div>
              <input
                type="range"
                min="0"
                max="15"
                step="0.1"
                value={tempThresholds.transformer}
                onChange={(e) => handleSliderChange('transformer', parseFloat(e.target.value))}
                className="w-full h-2 bg-vt-muted/20 rounded-lg appearance-none cursor-pointer slider"
              />
              <p className="text-xs text-vt-muted mt-1">Negative log-likelihood threshold for transformer model</p>
            </div>

            {/* Isolation Forest Threshold */}
            <div>
              <div className="flex justify-between items-center mb-2">
                <label className="text-sm font-medium text-vt-muted">Isolation Forest Threshold</label>
                <span className="text-sm font-mono text-vt-light">{tempThresholds.isolationForest.toFixed(2)}</span>
              </div>
              <input
                type="range"
                min="0"
                max="5"
                step="0.1"
                value={tempThresholds.isolationForest}
                onChange={(e) => handleSliderChange('isolationForest', parseFloat(e.target.value))}
                className="w-full h-2 bg-vt-muted/20 rounded-lg appearance-none cursor-pointer slider"
              />
              <p className="text-xs text-vt-muted mt-1">Anomaly score threshold for isolation forest</p>
            </div>

            <div className="border-t border-vt-muted/20 pt-4">
              <h4 className="text-sm font-semibold text-vt-muted mb-3">Model Weights</h4>
              
              {/* Rule-Based Weight */}
              <div className="mb-4">
                <div className="flex justify-between items-center mb-2">
                  <label className="text-sm font-medium text-vt-muted">Rule-Based Weight</label>
                  <span className="text-sm font-mono text-vt-light">{tempThresholds.ruleBasedWeight.toFixed(2)}</span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.1"
                  value={tempThresholds.ruleBasedWeight}
                  onChange={(e) => handleSliderChange('ruleBasedWeight', parseFloat(e.target.value))}
                  className="w-full h-2 bg-vt-muted/20 rounded-lg appearance-none cursor-pointer slider"
                />
              </div>

              {/* Isolation Forest Weight */}
              <div className="mb-4">
                <div className="flex justify-between items-center mb-2">
                  <label className="text-sm font-medium text-vt-muted">Isolation Forest Weight</label>
                  <span className="text-sm font-mono text-vt-light">{tempThresholds.isoForestWeight.toFixed(2)}</span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.1"
                  value={tempThresholds.isoForestWeight}
                  onChange={(e) => handleSliderChange('isoForestWeight', parseFloat(e.target.value))}
                  className="w-full h-2 bg-vt-muted/20 rounded-lg appearance-none cursor-pointer slider"
                />
              </div>

              {/* Transformer Weight */}
              <div>
                <div className="flex justify-between items-center mb-2">
                  <label className="text-sm font-medium text-vt-muted">Transformer Weight</label>
                  <span className="text-sm font-mono text-vt-light">{tempThresholds.transformerWeight.toFixed(2)}</span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.1"
                  value={tempThresholds.transformerWeight}
                  onChange={(e) => handleSliderChange('transformerWeight', parseFloat(e.target.value))}
                  className="w-full h-2 bg-vt-muted/20 rounded-lg appearance-none cursor-pointer slider"
                />
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex gap-3 pt-4 border-t border-vt-muted/20">
              <button
                onClick={handleReset}
                className="flex-1 px-4 py-2 bg-vt-muted/20 hover:bg-vt-muted/30 rounded-lg text-sm font-medium text-vt-light transition-colors"
              >
                Reset to Default
              </button>
              <button
                onClick={handleApply}
                className="flex-1 px-4 py-2 bg-vt-primary hover:bg-vt-primary/80 rounded-lg text-sm font-medium text-vt-dark transition-colors"
              >
                Apply Changes
              </button>
            </div>
          </div>
        </div>
      )}

      <style>{`
        .slider::-webkit-slider-thumb {
          appearance: none;
          width: 16px;
          height: 16px;
          border-radius: 50%;
          background: #0ef6cc;
          cursor: pointer;
        }

        .slider::-moz-range-thumb {
          width: 16px;
          height: 16px;
          border-radius: 50%;
          background: #0ef6cc;
          cursor: pointer;
          border: none;
        }

        .slider::-webkit-slider-thumb:hover {
          background: #08d9b5;
        }

        .slider::-moz-range-thumb:hover {
          background: #08d9b5;
        }
      `}</style>
    </div>
  );
};

export default ThresholdSettings;
