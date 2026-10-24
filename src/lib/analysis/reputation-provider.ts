/**
 * Threat Intelligence Provider Interface.
 * Handles external reputation queries safely with timeouts and explicit availability states.
 * Never fabricates lookups or guarantees safety when unconfigured.
 */

export interface ReputationResult {
  checked: boolean;
  providerName: string;
  isAvailable: boolean;
  isMalicious?: boolean;
  threatType?: string;
  details?: string;
  queryLatencyMs?: number;
}

export interface IReputationProvider {
  name: string;
  isConfigured(): boolean;
  lookupUrl(url: string): Promise<ReputationResult>;
}

/**
 * Standard Google Safe Browsing v4 or Cloud Web Risk Provider interface
 */
export class SafeBrowsingProvider implements IReputationProvider {
  name = 'Google Safe Browsing';
  private apiKey?: string;

  constructor(apiKey?: string) {
    this.apiKey = apiKey || process.env.SAFE_BROWSING_API_KEY;
  }

  isConfigured(): boolean {
    return Boolean(this.apiKey && this.apiKey.trim().length > 0 && this.apiKey !== 'MY_SAFE_BROWSING_KEY');
  }

  async lookupUrl(url: string): Promise<ReputationResult> {
    if (!this.isConfigured()) {
      return {
        checked: false,
        providerName: this.name,
        isAvailable: false,
        details: 'Threat intelligence API key not configured in environment. Local heuristic engine active.',
      };
    }

    const startTime = Date.now();
    try {
      // Abort controller with strict 3000ms timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);

      const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${this.apiKey}`;
      const payload = {
        client: {
          clientId: 'phishlens-detection-engine',
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!res.ok) {
        return {
          checked: false,
          providerName: this.name,
          isAvailable: false,
          details: `Reputation service returned HTTP ${res.status}. Falling back to local heuristics.`,
          queryLatencyMs: Date.now() - startTime,
        };
      }

      const data = await res.json() as { matches?: Array<{ threatType: string }> };
      const matches = data.matches || [];

      if (matches.length > 0) {
        return {
          checked: true,
          providerName: this.name,
          isAvailable: true,
          isMalicious: true,
          threatType: matches[0].threatType,
          details: `Flagged as ${matches[0].threatType} by threat intelligence feed.`,
          queryLatencyMs: Date.now() - startTime,
        };
      }

      return {
        checked: true,
        providerName: this.name,
        isAvailable: true,
        isMalicious: false,
        details: 'No known active threat match reported in threat feed.',
        queryLatencyMs: Date.now() - startTime,
      };
    } catch (err: unknown) {
      return {
        checked: false,
        providerName: this.name,
        isAvailable: false,
        details: `External lookup error: ${err instanceof Error ? err.message : 'timeout or network failure'}`,
        queryLatencyMs: Date.now() - startTime,
      };
    }
  }
}

/**
 * Mock provider for controlled offline unit testing
 */
export class MockReputationProvider implements IReputationProvider {
  name = 'Mock Threat Intelligence';
  private maliciousUrls: Set<string>;

  constructor(maliciousUrls: string[] = []) {
    this.maliciousUrls = new Set(maliciousUrls);
  }

  isConfigured(): boolean {
    return true;
  }

  async lookupUrl(url: string): Promise<ReputationResult> {
    const isMalicious = this.maliciousUrls.has(url);
    return {
      checked: true,
      providerName: this.name,
      isAvailable: true,
      isMalicious,
      threatType: isMalicious ? 'SOCIAL_ENGINEERING' : undefined,
      details: isMalicious ? 'Flagged in mock malicious database' : 'No threat detected in mock database',
      queryLatencyMs: 5,
    };
  }
}
