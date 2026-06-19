import React from 'react';
import ReactDOM from 'react-dom/client';
import type { DetectionResult } from '@/types/detection';

interface RiskDialogProps {
  result: DetectionResult;
  onDecision: (decision: 'proceed' | 'cancel') => void;
}

const RiskDialog: React.FC<RiskDialogProps> = ({ result, onDecision }) => {
  const { riskAssessment } = result;

  // AG-PROMPT-SURFACE-A11Y-VISUAL-REFINEMENT-020: WCAG AA compliant colors
  // CRITICAL = Indigo (regulatory importance), HIGH/MEDIUM = Slate
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#3730a3'; // Indigo
      case 'high': return '#334155';     // Slate
      case 'medium': return '#475569';   // Slate
      case 'low': return '#64748b';      // Slate
      default: return '#64748b';
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.3)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 2147483647,
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    }}>
      <div style={{
        backgroundColor: '#f8fafc',
        borderRadius: '6px',
        padding: '24px',
        maxWidth: '600px',
        width: '90%',
        maxHeight: '80vh',
        overflow: 'auto',
        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)'
      }}>
        <div style={{ marginBottom: '16px' }}>
          <h2 style={{
            margin: 0,
            fontSize: '18px',
            fontWeight: 600,
            color: '#0f172a',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
            <span style={{
              display: 'inline-block',
              width: '10px',
              height: '10px',
              borderRadius: '50%',
              backgroundColor: getSeverityColor(riskAssessment.overallSeverity)
            }} />
            Review before sharing
          </h2>
          <p style={{
            margin: '8px 0 0 0',
            fontSize: '14px',
            color: '#475569',
            lineHeight: 1.6
          }}>
            Indicators were detected in this file
          </p>
        </div>

        <div style={{
          backgroundColor: '#f8fafc',
          border: '1px solid #e2e8f0',
          borderRadius: '6px',
          padding: '12px',
          marginBottom: '16px'
        }}>
          <p style={{
            margin: 0,
            fontSize: '14px',
            color: '#0f172a',
            fontWeight: 500
          }}>
            Overall Severity: <span style={{ textTransform: 'uppercase' }}>
              {riskAssessment.overallSeverity}
            </span>
          </p>
        </div>

        <div style={{ marginBottom: '16px' }}>
          <h3 style={{
            margin: '0 0 12px 0',
            fontSize: '14px',
            fontWeight: 600,
            color: '#0f172a'
          }}>
            Detected Patterns
          </h3>
          <ul style={{
            margin: 0,
            padding: '0 0 0 20px',
            fontSize: '14px',
            color: '#475569',
            lineHeight: 1.6
          }}>
            {riskAssessment.matches.map((match, index) => (
              <li key={index} style={{ marginBottom: '8px' }}>
                <strong style={{ color: '#0f172a' }}>{match.patternName}</strong>: {match.description}
                {match.regulatoryBasis && (
                  <div style={{
                    fontSize: '12px',
                    color: '#64748b',
                    marginTop: '4px'
                  }}>
                    Regulatory basis: {match.regulatoryBasis}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>

        {riskAssessment.recommendations.length > 0 && (
          <div style={{ marginBottom: '16px' }}>
            <h3 style={{
              margin: '0 0 12px 0',
              fontSize: '14px',
              fontWeight: 600,
              color: '#0f172a'
            }}>
              Guidance
            </h3>
            <ul style={{
              margin: 0,
              padding: '0 0 0 20px',
              fontSize: '14px',
              color: '#475569',
              lineHeight: 1.6
            }}>
              {riskAssessment.recommendations.map((rec, index) => (
                <li key={index} style={{ marginBottom: '4px' }}>{rec}</li>
              ))}
            </ul>
          </div>
        )}

        <div style={{
          display: 'flex',
          gap: '12px',
          marginTop: '24px'
        }}>
          <button
            onClick={() => onDecision('cancel')}
            style={{
              flex: 1,
              padding: '12px 24px',
              fontSize: '14px',
              fontWeight: 500,
              color: '#64748b',
              backgroundColor: '#fff',
              border: '1px solid #e2e8f0',
              borderRadius: '6px',
              cursor: 'pointer'
            }}
          >
            Cancel Upload
          </button>
          <button
            onClick={() => onDecision('proceed')}
            style={{
              flex: 1,
              padding: '12px 24px',
              fontSize: '14px',
              fontWeight: 500,
              color: '#fff',
              backgroundColor: '#0f172a',
              border: '1px solid #0f172a',
              borderRadius: '6px',
              cursor: 'pointer'
            }}
          >
            Continue
          </button>
        </div>

        <p style={{
          margin: '16px 0 0 0',
          fontSize: '12px',
          color: '#64748b',
          textAlign: 'center',
          lineHeight: 1.5
        }}>
          This notification is for awareness only. You retain decision-making authority.
        </p>
      </div>
    </div>
  );
};

export function showRiskDialog(result: DetectionResult): Promise<'proceed' | 'cancel'> {
  return new Promise((resolve) => {
    const container = document.createElement('div');
    container.id = 'agentguard-risk-dialog';
    document.body.appendChild(container);

    const root = ReactDOM.createRoot(container);

    const handleDecision = (decision: 'proceed' | 'cancel') => {
      root.unmount();
      document.body.removeChild(container);
      resolve(decision);
    };

    root.render(
      <RiskDialog result={result} onDecision={handleDecision} />
    );
  });
}