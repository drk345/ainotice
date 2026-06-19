import React, { useState, useEffect } from 'react';
import type { LicenseStatus } from '@/types/license';

/**
 * AG-PROMPT-LICENSE-001: Popup license display
 *
 * Shows:
 * - VALID: "Active" badge, licensed features
 * - EXPIRED: "Courtesy Mode" badge + banner, features still shown
 * - INVALID: "Inactive" badge, contact admin message
 *
 * NO countdowns or "days left" displayed.
 */

interface LicenseResponse {
  valid: boolean;
  expired: boolean;
  features: string[];
  expiresAt: string | null;
  status?: LicenseStatus;
}

export const Popup: React.FC = () => {
  const [licenseData, setLicenseData] = useState<LicenseResponse | null>(null);

  useEffect(() => {
    loadStatus();
  }, []);

  const loadStatus = async () => {
    // AG-PHASE-1-RUNTIME-HARDENING-001: fail-open on extension disconnect
    try {
      const licenseResponse = await chrome.runtime.sendMessage({
        type: 'VALIDATE_LICENSE'
      });
      if (licenseResponse?.success) {
        setLicenseData(licenseResponse.data);
      }
    } catch {
      // Extension context invalidated — degrade gracefully
    }
  };

  // Compute display state from license data
  const getDisplayState = (): 'valid' | 'expired' | 'invalid' => {
    if (!licenseData) return 'invalid';
    // Prefer new canonical status if available
    if (licenseData.status) {
      return licenseData.status.state;
    }
    // Fallback to legacy fields
    if (licenseData.valid) return 'valid';
    if (licenseData.expired) return 'expired';
    return 'invalid';
  };

  const displayState = getDisplayState();
  const features = licenseData?.status?.features ?? licenseData?.features ?? [];

  const openOptions = () => {
    chrome.runtime.openOptionsPage();
  };

  // Status badge styling based on state
  const getStatusBadge = () => {
    switch (displayState) {
      case 'valid':
        return {
          text: 'Active',
          bg: '#d1fae5',
          color: '#065f46'
        };
      case 'expired':
        return {
          text: 'Courtesy Mode',
          bg: '#fef3c7',
          color: '#92400e'
        };
      case 'invalid':
      default:
        return {
          text: 'Inactive',
          bg: '#f1f5f9',
          color: '#64748b'
        };
    }
  };

  const badge = getStatusBadge();

  return (
    <div style={{ padding: '20px' }}>
      <div style={{ marginBottom: '20px' }}>
        <h1 style={{
          margin: '0 0 8px 0',
          fontSize: '24px',
          fontWeight: 600,
          color: '#0f172a'
        }}>
          Ai Notice
        </h1>
        <p style={{
          margin: 0,
          fontSize: '14px',
          color: '#475569'
        }}>
          Enterprise risk awareness
        </p>
      </div>

      {/* Courtesy Mode Banner (expired license) */}
      {displayState === 'expired' && (
        <div style={{
          backgroundColor: '#fffbeb',
          border: '1px solid #fcd34d',
          borderRadius: '8px',
          padding: '12px',
          marginBottom: '16px'
        }}>
          <div style={{
            fontSize: '13px',
            fontWeight: 500,
            color: '#92400e',
            marginBottom: '4px'
          }}>
            License expired
          </div>
          <div style={{
            fontSize: '12px',
            color: '#a16207',
            lineHeight: 1.4
          }}>
            This organization is using Ai Notice without an active license.
            Please contact your administrator.
          </div>
        </div>
      )}

      {/* Invalid License Banner */}
      {displayState === 'invalid' && (
        <div style={{
          backgroundColor: '#f8fafc',
          border: '1px solid #e2e8f0',
          borderRadius: '8px',
          padding: '12px',
          marginBottom: '16px'
        }}>
          <div style={{
            fontSize: '13px',
            fontWeight: 500,
            color: '#475569',
            marginBottom: '4px'
          }}>
            License not configured
          </div>
          <div style={{
            fontSize: '12px',
            color: '#64748b',
            lineHeight: 1.4
          }}>
            Please contact your administrator to set up licensing.
          </div>
        </div>
      )}

      <div style={{
        backgroundColor: '#f1f5f9',
        borderRadius: '8px',
        padding: '16px',
        marginBottom: '16px'
      }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '12px'
        }}>
          <span style={{
            fontSize: '14px',
            fontWeight: 500,
            color: '#334155'
          }}>
            License Status
          </span>
          <span style={{
            padding: '4px 8px',
            borderRadius: '4px',
            fontSize: '12px',
            fontWeight: 500,
            backgroundColor: badge.bg,
            color: badge.color
          }}>
            {badge.text}
          </span>
        </div>

        {/* Show features for valid OR expired (Courtesy Mode) */}
        {(displayState === 'valid' || displayState === 'expired') && features.length > 0 && (
          <div>
            <div style={{
              fontSize: '12px',
              color: '#475569',
              marginBottom: '8px'
            }}>
              {displayState === 'expired' ? 'Features (Courtesy Mode):' : 'Licensed Features:'}
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
              {features.map(feature => (
                <span
                  key={feature}
                  style={{
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '11px',
                    backgroundColor: displayState === 'expired' ? '#fef3c7' : '#dbeafe',
                    color: displayState === 'expired' ? '#92400e' : '#1e40af'
                  }}
                >
                  {feature}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      <button
        onClick={openOptions}
        style={{
          width: '100%',
          padding: '12px',
          fontSize: '14px',
          fontWeight: 500,
          color: 'white',
          backgroundColor: '#2563eb',
          border: 'none',
          borderRadius: '6px',
          cursor: 'pointer'
        }}
      >
        Open Settings
      </button>

      <div style={{
        marginTop: '16px',
        paddingTop: '16px',
        borderTop: '1px solid #e2e8f0',
        fontSize: '12px',
        color: '#475569',
        textAlign: 'center'
      }}>
        v1.0.0 • Privacy-first risk awareness
      </div>
    </div>
  );
};