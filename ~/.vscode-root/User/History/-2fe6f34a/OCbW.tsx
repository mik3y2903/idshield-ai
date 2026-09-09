import { FC } from 'react';
import { CURRENT_INSPECTION } from '../data/mockData';
import { RiskGauge } from '../components/RiskGauge';
import { RiskWaterfall } from '../components/RiskWaterfall';
import { EvidenceViewer } from '../components/EvidenceViewer';
import { StatusBadge } from '../components/StatusBadge';
import { 
  FileText, 
  QrCode, 
  ScanFace, 
  Sparkles, 
  Printer, 
  ArrowLeft 
} from 'lucide-react';

export const AnalysisResultPage: FC<{ 
  doc: DetailedAnalysis;
  onBack: () => void; 
  onOpenReport: () => void;
}> = ({ doc, onBack, onOpenReport }) => {
  const doc = CURRENT_INSPECTION;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white transition"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold text-white tracking-tight">Forensic Dossier: {doc.id}</h2>
              <StatusBadge status={doc.status} />
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Audited by {doc.processedByNode} on {doc.timestamp}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onOpenReport}
            className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition shadow-lg shadow-cyan-950"
          >
            <FileText className="w-3.5 h-3.5" />
            Generate Audit Report
          </button>
          <button
            onClick={() => window.print()}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white transition"
          >
            <Printer className="w-4 h-4" />
          </button>
        </div>
      </div>

      <div className="bg-rose-950/40 border border-rose-800/60 rounded-xl p-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-rose-500/20 border border-rose-500/40 flex items-center justify-center text-rose-400 font-bold text-lg">
            ⚠
          </div>
          <div>
            <h4 className="text-sm font-bold text-rose-200">High-Risk Manipulation Indicators Detected</h4>
            <p className="text-xs text-rose-300/80">
              Discrepancies identified across optical layout, QR cryptographic hashes, and microprint margins.
            </p>
          </div>
        </div>
        <span className="px-3 py-1 bg-rose-900/60 border border-rose-700 text-rose-200 rounded text-xs font-mono font-bold">
          CONFIDENCE: 92%
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
        <div className="md:col-span-4 bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col items-center justify-center text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
            Composite AI Risk Score
          </span>
          <RiskGauge score={doc.riskScore} />
          <div className="mt-3 text-xs text-slate-400 max-w-[240px]">
            Score indicates <strong className="text-rose-400">High Probability of Forgery</strong>. Multiple layout and hash deviations present.
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800 w-full grid grid-cols-2 text-center text-xs">
            <div>
              <span className="text-slate-500 block text-[10px]">VERIFICATION</span>
              <span className="text-rose-400 font-bold">REJECT / AUDIT</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">DOCUMENT CLASS</span>
              <span className="text-slate-200 font-bold">{doc.docType}</span>
            </div>
          </div>
        </div>

        <div className="md:col-span-8 bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-white">Signal Integrity Diagnostic Matrices</h3>
            <span className="text-xs text-slate-400 font-mono">Normalized Percentages</span>
          </div>

          <div className="space-y-3.5 my-3">
            {[
              { label: 'OCR Consistency & Text Sharpness', value: doc.ocrConfidence, color: 'bg-emerald-500' },
              { label: 'Layout & Template Alignment Integrity', value: doc.layoutIntegrity, color: 'bg-cyan-500' },
              { label: 'Pixel & Compression Error Level (ELA)', value: doc.imageIntegrity, color: 'bg-rose-500' },
              { label: 'Biometric Face Ratio Consistency', value: doc.faceConsistency, color: 'bg-emerald-500' },
            ].map((meter, i) => (
              <div key={i} className="space-y-1">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-300 font-medium">{meter.label}</span>
                  <span className="font-mono text-slate-300 font-bold">{meter.value}%</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div
                    style={{ width: `${meter.value}%` }}
                    className={`h-full ${meter.color} transition-all duration-700`}
                  />
                </div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-3 border-t border-slate-800 text-center">
            <div className="bg-slate-950/40 p-2 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 uppercase block">QR Hash Check</span>
              <span className="text-xs font-mono font-bold text-rose-400">FAILED</span>
            </div>
            <div className="bg-slate-950/40 p-2 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 uppercase block">Tampering Flag</span>
              <span className="text-xs font-mono font-bold text-rose-400">DETECTED</span>
            </div>
            <div className="bg-slate-950/40 p-2 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 uppercase block">Face Detected</span>
              <span className="text-xs font-mono font-bold text-emerald-400">YES (91% Q)</span>
            </div>
            <div className="bg-slate-950/40 p-2 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 uppercase block">Watermark</span>
              <span className="text-xs font-mono font-bold text-amber-400">DIFFUSED</span>
            </div>
          </div>
        </div>
      </div>

      <EvidenceViewer regions={doc.evidenceRegions} />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-white">Forensic Natural Language Explanations</h3>
          </div>
          <div className="p-3.5 rounded-lg bg-cyan-950/20 border border-cyan-800/40 text-xs text-cyan-200 leading-relaxed">
            The neural inference cluster classified this document with <strong>High Risk (78/100)</strong> primarily due to cryptographic payload corruption and localized text tampering.
          </div>
          <div className="space-y-2 text-xs">
            {doc.aiExplanation.map((reason, idx) => (
              <div key={idx} className="flex items-start gap-2 text-slate-300">
                <span className="text-cyan-400 font-bold mt-0.5">•</span>
                <span>{reason}</span>
              </div>
            ))}
          </div>
          <div className="pt-2 text-[11px] text-slate-500 font-mono">
            Analysis validated against Model Weights UID-FRAUD-DET-v9.82
          </div>
        </div>

        <div className="lg:col-span-6">
          <RiskWaterfall factors={doc.riskBreakdown} totalScore={doc.riskScore} />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
            <div className="flex items-center gap-2">
              <QrCode className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white">QR / Barcode Forensic Integrity</h3>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950 text-rose-300 border border-rose-800">
              STATUS: FAILED
            </span>
          </div>

          <div className="space-y-3 text-xs font-mono">
            <div className="bg-slate-950/60 p-2.5 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 uppercase block mb-1">Decoded Payload Digest</span>
              <span className="text-rose-300 break-all">{doc.qrDecodedData || 'NOT_DECODABLE'}</span>
            </div>
            <div className="bg-slate-950/60 p-2.5 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 uppercase block mb-1">Expected Template Schema</span>
              <span className="text-emerald-400 break-all">{doc.qrExpectedData}</span>
            </div>
            <div className="text-[11px] text-slate-400 font-sans">
              <strong>Forensic finding:</strong> The matrix dimensions do not conform to standardized v3 micro-QR specs. High likelihood of copy-paste from an unrelated legitimate credential.
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
            <div className="flex items-center gap-2">
              <ScanFace className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white">Biometric Facial Verification</h3>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-800">
              MATCH: 89%
            </span>
          </div>

          <div className="grid grid-cols-3 gap-3 text-center mb-4 text-xs">
            <div className="bg-slate-950/60 p-2 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 block">Face Present</span>
              <span className="font-bold text-emerald-400">YES</span>
            </div>
            <div className="bg-slate-950/60 p-2 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 block">Photo Quality</span>
              <span className="font-bold text-slate-200">91%</span>
            </div>
            <div className="bg-slate-950/60 p-2 rounded border border-slate-850">
              <span className="text-[10px] text-slate-500 block">Liveness Ratio</span>
              <span className="font-bold text-cyan-300">0.87</span>
            </div>
          </div>

          <div className="text-xs text-slate-400 space-y-1.5">
            <p>• Facial feature geometry matches standard identity distribution models.</p>
            <p className="text-amber-400">• However, boundary sharpness analysis suggests potential digital cut-and-paste onto background canvas.</p>
          </div>
        </div>
      </div>
    </div>
  );
};