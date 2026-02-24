import React, { useState } from 'react';
import Button from './Button';

interface OrgCreationResultProps {
  orgId: string;
  orgName: string;
  managerEmail: string;
  managerPassword: string;
  onClose: () => void;
}

const OrgCreationResult: React.FC<OrgCreationResultProps> = ({
  orgId,
  orgName,
  managerEmail,
  managerPassword,
  onClose
}) => {
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const copyToClipboard = async (text: string, fieldName: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(fieldName);
      setTimeout(() => setCopiedField(null), 2000);
    } catch (err) {
      console.error('Failed to copy text: ', err);
    }
  };

  const CopyButton: React.FC<{ text: string; fieldName: string }> = ({ text, fieldName }) => (
    <Button
      size="sm"
      onClick={() => copyToClipboard(text, fieldName)}
      className="ml-2 bg-slate-600 hover:bg-slate-500 text-xs px-2 py-1"
    >
      {copiedField === fieldName ? 'Copied!' : 'Copy'}
    </Button>
  );

  return (
    <div className="space-y-6">
      <div className="text-center">
        <div className="w-16 h-16 bg-green-500 rounded-full flex items-center justify-center mx-auto mb-4">
          <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <h3 className="text-lg font-semibold text-white mb-2">Organization Created Successfully!</h3>
        <p className="text-slate-400 text-sm">
          Please save these credentials securely. They will not be shown again.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="bg-slate-700/30 rounded-lg p-4">
          <label className="block text-sm font-medium text-slate-300 mb-2">Organization ID</label>
          <div className="flex items-center gap-2">
            <code className="flex-1 bg-slate-800 px-3 py-2 rounded text-slate-200 font-mono text-sm break-all">
              {orgId}
            </code>
            <CopyButton text={orgId} fieldName="orgId" />
          </div>
        </div>

        <div className="bg-slate-700/30 rounded-lg p-4">
          <label className="block text-sm font-medium text-slate-300 mb-2">Organization Name</label>
          <div className="flex items-center gap-2">
            <code className="flex-1 bg-slate-800 px-3 py-2 rounded text-slate-200 font-mono text-sm break-all">
              {orgName}
            </code>
            <CopyButton text={orgName} fieldName="orgName" />
          </div>
        </div>

        <div className="bg-slate-700/30 rounded-lg p-4">
          <label className="block text-sm font-medium text-slate-300 mb-2">Manager Email</label>
          <div className="flex items-center gap-2">
            <code className="flex-1 bg-slate-800 px-3 py-2 rounded text-slate-200 font-mono text-sm break-all">
              {managerEmail}
            </code>
            <CopyButton text={managerEmail} fieldName="managerEmail" />
          </div>
        </div>

        <div className="bg-slate-700/30 rounded-lg p-4">
          <label className="block text-sm font-medium text-slate-300 mb-2">Manager Password</label>
          <div className="flex items-center gap-2">
            <code className="flex-1 bg-slate-800 px-3 py-2 rounded text-slate-200 font-mono text-sm break-all">
              {managerPassword}
            </code>
            <CopyButton text={managerPassword} fieldName="managerPassword" />
          </div>
          <p className="text-xs text-amber-400 mt-2">
            ⚠️ This is a temporary password. The manager should change it after first login.
          </p>
        </div>
      </div>

      <div className="flex justify-end pt-4 border-t border-slate-700">
        <Button onClick={onClose} className="bg-vt-primary hover:bg-vt-primary/80">
          Done
        </Button>
      </div>
    </div>
  );
};

export default OrgCreationResult;