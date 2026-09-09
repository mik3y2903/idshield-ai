export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type VerificationStatus = 'VERIFIED' | 'SUSPICIOUS' | 'HIGH RISK' | 'CRITICAL';

export interface DocumentRecord {
  id: string;
  docType: 'Aadhaar' | 'PAN Card' | 'Passport' | 'Voter ID' | 'Driving License';
  subjectMaskedId: string;
  riskScore: number;
  ocrConfidence: number;
  tamperingDetected: boolean;
  qrStatus: 'VERIFIED' | 'FAILED' | 'MISSING' | 'MISMATCH';
  status: VerificationStatus;
  timestamp: string;
  processedByNode: string;
}

export interface RiskFactor {
  signal: string;
  weight: number;
  impact: 'positive' | 'negative';
  description: string;
}

export interface EvidenceRegion {
  id: string;
  label: string;
  confidence: number;
  x: number; // percentage
  y: number; // percentage
  width: number; // percentage
  height: number; // percentage
  type: 'font_anomaly' | 'qr_forgery' | 'pixel_splice' | 'layout_shift';
  explanation: string;
}

export interface DetailedAnalysis extends DocumentRecord {
  layoutIntegrity: number;
  imageIntegrity: number;
  faceConsistency: number;
  faceDetected: boolean;
  faceQuality: number;
  qrDecodedData: string | null;
  qrExpectedData: string | null;
  aiExplanation: string[];
  riskBreakdown: RiskFactor[];
  evidenceRegions: EvidenceRegion[];
}

export type PipelineStage = 
  | 'upload'
  | 'preprocessing'
  | 'ocr'
  | 'classification'
  | 'tampering'
  | 'layout'
  | 'qr'
  | 'biometric'
  | 'risk'
  | 'decision';

export interface StageStatus {
  id: PipelineStage;
  label: string;
  state: 'pending' | 'processing' | 'completed' | 'failed';
  details?: string;
}