import React, { useState } from 'react';
import Button from './Button';

interface ProjectCreationResultProps {
  projectId: string;
  projectName: string;
  apiKey: string;
  onClose: () => void;
}

const ProjectCreationResult: React.FC<ProjectCreationResultProps> = ({
  projectId,
  apiKey,
  onClose,
}) => {
  const [copiedApiKey, setCopiedApiKey] = useState(false);

  const handleCopyApiKey = async () => {
    try {
      await navigator.clipboard.writeText(apiKey);
      setCopiedApiKey(true);
      setTimeout(() => setCopiedApiKey(false), 2000);
    } catch (err) {
      console.error('Failed to copy API key:', err);
    }
  };

  return (
    <div className="space-y-6">

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Project ID
          </label>
          <div className="px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg">
            <code className="text-sm text-slate-300 font-mono break-all">{projectId}</code>
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            API Key
          </label>
          <div className="relative">
            <div className="px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg pr-24">
              <code className="text-sm text-green-400 font-mono break-all">{apiKey}</code>
            </div>
            <Button
              onClick={handleCopyApiKey}
              size="sm"
              className="absolute right-2 top-1/2 -translate-y-1/2 bg-vt-primary hover:bg-vt-primary/80"
            >
              {copiedApiKey ? 'Copied!' : 'Copy'}
            </Button>
          </div>
        </div>
      </div>

      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <svg className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <div className="flex-1">
            <h4 className="text-sm font-semibold text-yellow-400 mb-1">Important</h4>
            <p className="text-yellow-300 text-sm">
              Please save this API key securely. You will not be able to see it again after closing this dialog.
              You can regenerate a new key from the project dashboard if needed.
            </p>
          </div>
        </div>
      </div>

      <div className="flex justify-end pt-2">
        <Button
          onClick={onClose}
          className="bg-vt-primary hover:bg-vt-primary/80 px-6 py-2"
        >
          Done
        </Button>
      </div>
    </div>
  );
};

export default ProjectCreationResult;
