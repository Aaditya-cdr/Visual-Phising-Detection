/**
 * Quick synthetic test fixtures for demonstrable verification of phishing signals
 */

import React from 'react';
import { Globe, Mail, MessageSquare, AlertTriangle, ShieldCheck } from 'lucide-react';

export interface TestPreset {
  id: string;
  label: string;
  type: 'url' | 'email' | 'message';
  description: string;
  expectedCategory: 'SUSPICIOUS' | 'NEEDS_REVIEW' | 'NO_EVIDENCE_FOUND';
  data: {
    url?: string;
    text?: string;
    sender?: string;
  };
}

export const TEST_PRESETS: TestPreset[] = [
  {
    id: 'paypal-typosquat',
    label: 'Brand Lookalike URL',
    type: 'url',
    description: 'Typosquatting & confusable domain impersonating PayPal',
    expectedCategory: 'SUSPICIOUS',
    data: {
      url: 'https://paypa1-security.com/verify-account',
    },
  },
  {
    id: 'ip-address-host',
    label: 'Direct IP Host',
    type: 'url',
    description: 'Bare IP address with credential keywords in path',
    expectedCategory: 'SUSPICIOUS',
    data: {
      url: 'http://185.220.101.5/banking-login',
    },
  },
  {
    id: 'suspicious-tld',
    label: 'High-Abuse Disposable TLD',
    type: 'url',
    description: 'Disposable .xyz domain with authentication path',
    expectedCategory: 'NEEDS_REVIEW',
    data: {
      url: 'https://secure-portal-update.xyz/login',
    },
  },
  {
    id: 'google-legitimate',
    label: 'Legitimate Official Domain',
    type: 'url',
    description: 'Verified official public service domain',
    expectedCategory: 'NO_EVIDENCE_FOUND',
    data: {
      url: 'https://accounts.google.com/signin',
    },
  },
  {
    id: 'urgent-suspension-email',
    label: 'Account Suspension Email',
    type: 'email',
    description: 'Urgency, password solicitation, and sender mismatch',
    expectedCategory: 'SUSPICIOUS',
    data: {
      sender: 'security-alerts@paypal-notice.com',
      text: 'URGENT SECURITY NOTICE: Your account has been temporarily restricted due to unauthorized login attempts detected from an unknown device.\n\nImmediate verification is required within 24 hours. Failure to respond will result in permanent account termination.\n\nClick the link below to confirm your password and restore access:\nhttps://paypa1-security.com/unlock-account',
    },
  },
  {
    id: 'parcel-scam-sms',
    label: 'Fake Delivery SMS',
    type: 'message',
    description: 'Parcel delivery fee lure with disposable link',
    expectedCategory: 'SUSPICIOUS',
    data: {
      text: 'USPS Alert: Package tracking #9400111899562 cannot be delivered due to an unpaid shipping fee of $2.45. Please settle fee before 6 PM at https://usps-redelivery.top/pay to avoid package return.',
    },
  },
  {
    id: 'clean-work-message',
    label: 'Benign Business Message',
    type: 'message',
    description: 'Ordinary neutral communication with no threats or credential prompts',
    expectedCategory: 'NO_EVIDENCE_FOUND',
    data: {
      text: 'Hi team, the slides for our architecture review tomorrow have been shared in the project repository. Please review before 2 PM.',
    },
  },
];

interface PresetBarProps {
  onSelectPreset: (preset: TestPreset) => void;
}

export const PresetBar: React.FC<PresetBarProps> = ({ onSelectPreset }) => {
  return (
    <div className="w-full mb-6">
      <div className="flex items-center justify-between mb-2.5">
        <span className="text-xs font-semibold text-slate-400 tracking-wider uppercase">
          Quick Test Scenarios
        </span>
        <span className="text-xs text-slate-500">
          Synthetic fixtures to demonstrate detection rules
        </span>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
        {TEST_PRESETS.map((preset) => {
          const isSuspicious = preset.expectedCategory === 'SUSPICIOUS';
          const isReview = preset.expectedCategory === 'NEEDS_REVIEW';
          
          return (
            <button
              key={preset.id}
              onClick={() => onSelectPreset(preset)}
              className="text-left p-2.5 rounded-lg border border-slate-800 bg-slate-900/60 hover:bg-slate-800/80 hover:border-slate-700 transition-all group"
            >
              <div className="flex items-center justify-between gap-1 mb-1">
                <span className="text-xs font-medium text-slate-200 group-hover:text-sky-300 transition-colors truncate">
                  {preset.label}
                </span>
                {isSuspicious ? (
                  <AlertTriangle className="w-3 h-3 text-red-400 shrink-0" />
                ) : isReview ? (
                  <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0" />
                ) : (
                  <ShieldCheck className="w-3 h-3 text-emerald-400 shrink-0" />
                )}
              </div>
              <div className="text-[11px] text-slate-500 leading-snug line-clamp-1">
                {preset.description}
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
};
