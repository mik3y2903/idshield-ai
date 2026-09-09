import React, { useState } from 'react';
import { StageStatus, PipelineStage } from '../types';
import { 
  UploadCloud, 
  Camera, 
  File, 
  CheckCircle2, 
  Loader2, 
  AlertCircle, 
  ShieldCheck, 
  ArrowRight 
} from 'lucide-react';

const INITIAL_STAGES: StageStatus[] = [
  { id: 'upload', label: 'Payload Receiving & Hash Check', state: 'pending' },
  { id: 'preprocessing', label: 'Image Rectification & ELA Normalization', state: 'pending' },
  { id: 'ocr', label: 'Deep OCR & Key-Value Extraction', state: 'pending' },
  { id: 'classification', label: 'Document Template Classifier', state: 'pending' },
  { id: 'tampering', label: 'Splice & Pixel Anomaly Detection', state: 'pending' },
  { id: 'layout', label: 'Microprint & Layout Structural Check', state: 'pending' },
  { id: 'qr', label: 'Cryptographic QR Code Validation', state: 'pending' },
  { id: 'biometric', label: 'Face Quality & Photo Integrity Check', state: 'pending' },
  { id: 'risk', label: 'Explainable Multi-Signal Risk Engine', state: 'pending' },
  { id: 'decision', label: 'Final Forensic Verdict Synthesis', state: 'pending' }
];

export const ScreeningPage: React.FC<{ onCompleteAnalysis: () => void }> = ({ onCompleteAnalysis }) => {
  const [stages, setStages] = useState<StageStatus[]>(INITIAL_STAGES);
  const [isProcessing, setIsProcessing] = useState(false);
  const [fileUploaded, setFileUploaded] = useState(false);

  const startPipelineSimulation = () => {
    setIsProcessing(true);
    setFileUploaded(true);

    INITIAL_STAGES.forEach((_, index) => {
      setTimeout(() => {
        setStages((prev) =>
          prev.map((stage, idx) => {
            if (idx < index) return { ...stage, state: 'completed' };
            if (idx === index) return { ...stage, state: 'processing' };
            return { ...stage, state: 'pending' };
          })
        );
      }, (index + 1) * 350);
    });

    setTimeout(() => {
      setStages((prev) => prev.map((s) => ({ ...s, state: 'completed' })));
      setIsProcessing(false);
    }, (INITIAL_STAGES.length + 1) * 350);
  };

  const isFinished = stages.every((s) => s.state === 'completed');

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight">Identity Document Upload & Screening Engine</h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Execute real-time optical character recognition, digital watermark verification, and convolutional tampering analysis.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Upload Zone */}
        <div className="lg:col-span-7 space-y-4">
          <div className="border-2 border-dashed border-slate-700 hover:border-cyan-500/60 bg-slate-900/60 rounded-2xl p-8 flex flex-col items-center justify-center text-center transition">
            <div className="w-16 h-16 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mb-4">
              <UploadCloud className="w-8 h-8" />
            </div>
            <h3 className="text-base font-semibold text-white mb-1">Upload Identity Document</h3>
            <p className="text-xs text-slate-400 max-w-sm mb-4 leading-relaxed">
              Drag and drop high-resolution JPG, PNG, or single-page PDF files. Standard Indian ID cards (Aadhaar, PAN, Passport, Voter ID) are automatically recognized.
            </p>

            <div className="flex flex-wrap items-center justify-center gap-3">
              <button
                onClick={startPipelineSimulation}
                disabled={isProcessing}
                className="px-5 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition flex items-center gap-2 shadow-lg shadow-cyan-950 disabled:opacity-50"
              >
                <File className="w-4 h-4" />
                Select File & Run AI Verification
              </button>

              <button
                disabled={isProcessing}
                className="px-4 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs border border-slate-700 transition flex items-center gap-2"
              >
                <Camera className="w-4 h-4 text-cyan-400" />
                Hardware Scanner / Camera
              </button>
            </div>

            <div className="mt-6 flex items-center gap-4 text-[11px] text-slate-500 border-t border-slate-800/80 pt-4">
              <span>Max file size: 25MB</span>
              <span>•</span>
              <span className="flex items-center gap-1 text-slate-400">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> End-to-End TLS Encrypted
              </span>
            </div>
          </div>

          {fileUploaded && (
            <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded bg-slate-800 flex items-center justify-center text-cyan-400">
                  <File className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-xs font-semibold text-white">aadhaar_scan_suspect_doc8421.png</div>
                  <div className="text-[10px] text-slate-400">2.4 MB • Image/PNG • MD5: 9a7e8b2...01c</div>
                </div>
              </div>
              <span className="text-xs font-mono text-cyan-400 font-bold">
                {isProcessing ? 'Processing...' : 'Analyzed'}
              </span>
            </div>
          )}
        </div>

        {/* Verification Pipeline Progress */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
              <h3 className="text-sm font-semibold text-white">AI Analysis Pipeline Execution</h3>
              <span className="text-[11px] font-mono text-cyan-400">10 Verification Checks</span>
            </div>

            <div className="space-y-2.5">
              {stages.map((stage, idx) => {
                return (
                  <div
                    key={stage.id}
                    className="flex items-center justify-between text-xs p-2 rounded-lg bg-slate-950/40 border border-slate-850"
                  >
                    <div className="flex items-center gap-2.5">
                      <span className="w-5 h-5 rounded-full bg-slate-800 text-slate-400 text-[10px] flex items-center justify-center font-mono font-bold">
                        {idx + 1}
                      </span>
                      <span className={`${
                        stage.state === 'processing' ? 'text-cyan-300 font-semibold' : stage.state === 'completed' ? 'text-slate-300' : 'text-slate-500'
                      }`}>
                        {stage.label}
                      </span>
                    </div>

                    <div>
                      {stage.state === 'pending' && <span className="text-[10px] text-slate-600 uppercase font-mono">Pending</span>}
                      {stage.state === 'processing' && (
                        <span className="flex items-center gap-1 text-[10px] text-cyan-400 font-mono">
                          <Loader2 className="w-3 h-3 animate-spin" /> RUNNING
                        </span>
                      )}
                      {stage.state === 'completed' && (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      )}
                      {stage.state === 'failed' && (
                        <AlertCircle className="w-4 h-4 text-rose-400" />
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800 mt-4">
            <button
              onClick={onCompleteAnalysis}
              disabled={!isFinished}
              className={`w-full py-2.5 rounded-lg text-xs font-bold transition flex items-center justify-center gap-2 ${
                isFinished 
                  ? 'bg-cyan-500 hover:bg-cyan-400 text-slate-950 cursor-pointer shadow-lg shadow-cyan-950'
                  : 'bg-slate-800 text-slate-500 cursor-not-allowed'
              }`}
            >
              Open Complete Forensic Analysis <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};