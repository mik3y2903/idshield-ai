import React, { useState } from 'react';
import { Shield, Key, User, Lock, AlertTriangle, Eye, EyeOff, Terminal, UserPlus, CheckCircle2 } from 'lucide-react';

interface LoginPageProps {
  onLoginSuccess: (officer: { badgeId: string; name: string; clearance: string }) => void;
}

const CLEARANCE_MAP: Record<string, string> = {
  L1: 'Verification Observer',
  L2: 'Forensic Examiner',
  L3: 'Gov. Lead Investigator',
  L4: 'Autonomous Syndicate Admin',
};

export const LoginPage: React.FC<LoginPageProps> = ({ onLoginSuccess }) => {
  const [isRegisterMode, setIsRegisterMode] = useState(false);
  const [badgeId, setBadgeId] = useState('INV-7029');
  const [password, setPassword] = useState('');
  const [agencyKey, setAgencyKey] = useState('');
  const [clearanceLevel, setClearanceLevel] = useState('L3');
  const [showPassword, setShowPassword] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    setSuccessMsg('');
    setIsSubmitting(true);

    const endpoint = isRegisterMode 
      ? 'http://localhost:8000/api/auth/register' 
      : 'http://localhost:8000/api/auth/token';

    const payload = isRegisterMode
      ? { badgeId, password, clearanceLevel, agencySecretKey: agencyKey }
      : { badgeId, password, clearanceLevel };

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Authentication service rejected the request.');
      }

      if (isRegisterMode) {
        setSuccessMsg(data.message || 'Authorization granted. You can now login.');
        setIsRegisterMode(false);
        setPassword('');
        setAgencyKey('');
      } else {
        onLoginSuccess({
          badgeId: data.officer.badgeId,
          name: CLEARANCE_MAP[data.officer.clearance] || data.officer.name,
          clearance: data.officer.clearance,
        });
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Connection failure to active auth cluster.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="relative min-h-screen w-full bg-slate-950 flex items-center justify-center p-4 overflow-hidden select-none">
      {/* Tactical Background Grid & Vignette */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#0f172a_1px,transparent_1px),linear-gradient(to_bottom,#0f172a_1px,transparent_1px)] bg-[size:3rem_3rem] opacity-40 pointer-events-none" />

      <div className="relative w-full max-w-md bg-slate-900/90 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-[0_0_50px_-12px_rgba(6,182,212,0.25)] p-8 z-10">
        
        {/* Header Branding */}
        <div className="flex flex-col items-center text-center mb-6">
          <div className="relative flex items-center justify-center w-14 h-14 rounded-xl bg-slate-800/80 border border-cyan-500/40 shadow-[0_0_20px_rgba(6,182,212,0.3)] mb-3">
            <Shield className="w-7 h-7 text-cyan-400 animate-pulse" />
          </div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-mono font-bold tracking-wider text-slate-100 uppercase">
              IDSHIELD <span className="text-cyan-400">AI</span>
            </h1>
            <span className="px-1.5 py-0.5 text-[10px] font-mono bg-cyan-950/80 text-cyan-400 border border-cyan-500/30 rounded">
              v2.4-PROD
            </span>
          </div>
          <p className="text-xs text-slate-400 tracking-wide mt-1">
            Forensic Identity & Syndicate Threat Detection Console
          </p>
        </div>

        {/* Access vs Register Mode Toggle */}
        <div className="flex rounded-lg bg-slate-950 p-1 border border-slate-800 mb-6">
          <button
            type="button"
            onClick={() => { setIsRegisterMode(false); setErrorMsg(''); setSuccessMsg(''); }}
            className={`flex-1 py-1.5 text-xs font-mono font-semibold rounded transition-colors ${
              !isRegisterMode 
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' 
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Access Session
          </button>
          <button
            type="button"
            onClick={() => { setIsRegisterMode(true); setErrorMsg(''); setSuccessMsg(''); }}
            className={`flex-1 py-1.5 text-xs font-mono font-semibold rounded transition-colors ${
              isRegisterMode 
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' 
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Register Profile
          </button>
        </div>

        {/* Status Alerts */}
        {errorMsg && (
          <div className="mb-4 flex items-start space-x-2 p-3 rounded-lg bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs font-mono">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <span>{errorMsg}</span>
          </div>
        )}
        {successMsg && (
          <div className="mb-4 flex items-start space-x-2 p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 text-xs font-mono">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <span>{successMsg}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Badge ID */}
          <div>
            <label className="block text-[11px] font-mono tracking-wider text-slate-400 uppercase mb-1">
              Investigator Badge ID
            </label>
            <div className="relative">
              <User className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
              <input
                type="text"
                required
                value={badgeId}
                onChange={(e) => setBadgeId(e.target.value)}
                placeholder="e.g., INV-7029"
                className="w-full pl-9 pr-3 py-2 bg-slate-950/70 border border-slate-800 rounded-lg text-sm text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
              />
            </div>
          </div>

          {/* Agency Secret Key (Register Mode Only) */}
          {isRegisterMode && (
            <div>
              <label className="block text-[11px] font-mono tracking-wider text-amber-400 uppercase mb-1">
                Agency Authorization Secret Key
              </label>
              <div className="relative">
                <Key className="absolute left-3 top-2.5 w-4 h-4 text-amber-500" />
                <input
                  type="password"
                  required
                  value={agencyKey}
                  onChange={(e) => setAgencyKey(e.target.value)}
                  placeholder="Master Agency Key"
                  className="w-full pl-9 pr-3 py-2 bg-slate-950/70 border border-amber-500/40 rounded-lg text-sm text-amber-200 font-mono focus:border-amber-400 focus:outline-none"
                />
              </div>
            </div>
          )}

          {/* Passcode */}
          <div>
            <label className="block text-[11px] font-mono tracking-wider text-slate-400 uppercase mb-1">
              {isRegisterMode ? 'New Access Passphrase' : 'Security Clearance Key'}
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter passphrase"
                className="w-full pl-9 pr-10 py-2 bg-slate-950/70 border border-slate-800 rounded-lg text-sm text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Clearance Level Selector */}
          <div>
            <label className="block text-[11px] font-mono tracking-wider text-slate-400 uppercase mb-1">
              Station Clearance Profile
            </label>
            <select
              value={clearanceLevel}
              onChange={(e) => setClearanceLevel(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950/70 border border-slate-800 rounded-lg text-xs text-slate-300 font-mono focus:border-cyan-500 focus:outline-none"
            >
              <option value="L1">Level 1: Verification Observer</option>
              <option value="L2">Level 2: Forensic Examiner</option>
              <option value="L3">Level 3: Gov. Lead Investigator (Full Access)</option>
              <option value="L4">Level 4: Autonomous Syndicate Admin</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full mt-2 py-2.5 px-4 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-semibold uppercase tracking-wider rounded-lg shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all flex items-center justify-center space-x-2 disabled:opacity-50"
          >
            {isSubmitting ? (
              <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
            ) : isRegisterMode ? (
              <>
                <UserPlus className="w-4 h-4" />
                <span>Register Clearance Profile</span>
              </>
            ) : (
              <>
                <Key className="w-4 h-4" />
                <span>Initialize Secure Session</span>
              </>
            )}
          </button>
        </form>

        {/* Footer Hardware Indicator */}
        <div className="mt-6 pt-4 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-500">
          <div className="flex items-center space-x-1.5">
            <Terminal className="w-3 h-3 text-cyan-500" />
            <span>KALI-CLUSTER-01</span>
          </div>
          <span className="text-emerald-400 flex items-center space-x-1">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
            <span>SECURE ENCLAVE</span>
          </span>
        </div>
      </div>
    </div>
  );
};