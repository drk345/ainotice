import { handleMessage } from './message-handler';
import { validateLicense } from './license-validator';

console.log('AgentGuard background service worker started');

// Initialize on installation
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    console.log('AgentGuard installed');
    
    // Validate license on first install
    const licenseResult = await validateLicense();
    if (!licenseResult.valid) {
      console.warn('Invalid or missing license:', licenseResult.error);
    }
    
    // Set default settings
    try {
      await chrome.storage.local.set({
        settings: {
          enabledPacks: [],
          restrictedMode: false
        }
      });
    } catch (e) {
      console.warn('[AgentGuard] storage.set(settings) failed on install:', (e as Error).message);
    }
  }
});

// Message handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then(sendResponse)
    .catch((error) => {
      console.error('Message handling error:', error);
      sendResponse({
        success: false,
        error: error.message
      });
    });
  
  return true; // Async response
});

// Keep service worker alive
chrome.runtime.onConnect.addListener((port) => {
  console.log('Content script connected');
});