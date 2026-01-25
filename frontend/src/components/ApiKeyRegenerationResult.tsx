import React, { useState } from 'react';
import Button from './Button';

interface ApiKeyRegenerationResultProps {
  orgId: string;
  newApiKey: string;
  onClose: () => void;
}

const ApiKeyRegenerationResult: React.FC<ApiKeyRegenerationResultProps> = ({
  orgId,
  newApiKey,
  onClose
}) => {
  const [copied, setCopied] = useState(false);

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy text: ', err);
    }
  };

  return (
    <div className="space-y-6">
      <div className="text-center">
        <div className="w-16 h-16 bg-blue-500 rounded-full flex items-center justify-center mx-auto mb-4">
          <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
          </svg>
        </div>
        <h3 className="text-lg font-semibold text-white mb-2">API Key Regenerated</h3>
        <p className="text-slate-400 text-sm">
          The old API key has been invalidated. Update any systems using the old key.
        </p>
      </div>

      <div className="bg-slate-700 rounded-lg p-4">
        <label className="block text-sm font-medium text-slate-300 mb-2">Organization ID</label>
        <code className="block bg-slate-800 px-3 py-2 rounded text-slate-200 font-mono text-sm">
          {orgId}
        </code>
      </div>

      <div className="bg-slate-700 rounded-lg p-4">
        <label className="block text-sm font-medium text-slate-300 mb-2">New API Key</label>
        <div className="flex items-center gap-2">
          <code className="flex-1 bg-slate-800 px-3 py-2 rounded text-slate-200 font-mono text-sm break-all">
            {newApiKey}
          </code>
          <Button
            size="sm"
            onClick={() => copyToClipboard(newApiKey)}
            className="bg-slate-600 hover:bg-slate-500 text-xs px-2 py-1"
          >
            {copied ? 'Copied!' : 'Copy'}
          </Button>
        </div>
        <p className="text-xs text-amber-400 mt-2">
          ⚠️ Keep this key secure and update all your systems immediately
        </p>
      </div>

      <div className="flex justify-end pt-4 border-t border-slate-700">
        <Button onClick={onClose} className="bg-vt-primary hover:bg-vt-primary/80">
          Done
        </Button>
      </div>
    </div>
  );
};

export default ApiKeyRegenerationResult;