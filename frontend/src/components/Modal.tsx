import React from 'react';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}

const Modal: React.FC<ModalProps> = ({ isOpen, onClose, title, children }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop with blur */}
      <button
        type="button"
        aria-label={`Close ${title}`}
        className="absolute inset-0 bg-slate-950/72 backdrop-blur-md"
        onClick={onClose}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            onClose();
          }
        }}
      />

      {/* Modal */}
      <div className="relative max-h-[90vh] w-full max-w-5xl overflow-y-auto rounded-[28px] border border-white/8 bg-[linear-gradient(180deg,rgba(15,23,42,0.98),rgba(8,15,29,0.95))] shadow-[0_28px_80px_rgba(2,8,23,0.55)]">
        <div className="p-6 sm:p-7">
          <div className="mb-5 flex items-center justify-between gap-4 border-b border-white/6 pb-4">
            <h2 className="text-xl font-semibold text-slate-50 sm:text-2xl">{title}</h2>
            <button
              type="button"
              onClick={onClose}
              className="rounded-full border border-white/10 p-2 text-slate-400 transition hover:bg-white/[0.05] hover:text-white"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          {children}
        </div>
      </div>
    </div>
  );
};

export default Modal;
