#!/usr/bin/env node

// Enhanced Rate Limiting Testing and Monitoring Tool
const axios = require('axios').default;
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

class RateLimitTester {
  constructor() {
    this.baseUrl = process.env.APP_BASE_URL || 'http://localhost:3000';
    this.testResults = [];
  }

  /**
   * Display main menu
   */
  async showMenu() {
    console.log('\n🔒 ENHANCED RATE LIMITING TESTER');
    console.log('================================');
    console.log('1. Test device fingerprinting');
    console.log('2. Simulate rate limiting attack');
    console.log('3. Compare normal vs suspicious requests');
    console.log('4. Test different user agents');
    console.log('5. Benchmark fingerprinting performance');
    console.log('6. Monitor rate limit statistics');
    console.log('7. Test specific auth endpoints');
    console.log('8. Export test results');
    console.log('9. Exit');
    console.log('================================');

    const choice = await this.prompt('Select option (1-9): ');
    await this.handleMenuChoice(choice);
  }

  /**
   * Handle menu selection
   */
  async handleMenuChoice(choice) {
    switch (choice) {
      case '1':
        await this.testDeviceFingerprinting();
        break;
      case '2':
        await this.simulateRateLimitAttack();
        break;
      case '3':
        await this.compareNormalVsSuspicious();
        break;
      case '4':
        await this.testDifferentUserAgents();
        break;
      case '5':
        await this.benchmarkPerformance();
        break;
      case '6':
        await this.monitorStatistics();
        break;
      case '7':
        await this.testAuthEndpoints();
        break;
      case '8':
        await this.exportResults();
        break;
      case '9':
        console.log('👋 Goodbye!');
        process.exit(0);
        break;
      default:
        console.log('❌ Invalid option');
    }

    // Show menu again
    setTimeout(() => this.showMenu(), 1000);
  }

  /**
   * Test device fingerprinting
   */
  async testDeviceFingerprinting() {
    console.log('\n📱 Testing Device Fingerprinting');
    console.log('--------------------------------');

    const testCases = [
      {
        name: 'Chrome on Windows',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
          'Accept-Language': 'en-US,en;q=0.9',
          'Accept-Encoding': 'gzip, deflate, br',
          'Sec-Ch-Ua': '"Chromium";v="91", " Not A;Brand";v="99"',
          'Sec-Ch-Ua-Mobile': '?0',
          'Sec-Ch-Ua-Platform': '"Windows"'
        }
      },
      {
        name: 'Firefox on Linux',
        headers: {
          'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
          'Accept-Language': 'en-US,en;q=0.5',
          'Accept-Encoding': 'gzip, deflate'
        }
      },
      {
        name: 'Safari on macOS',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
          'Accept-Language': 'en-us',
          'Accept-Encoding': 'gzip, deflate'
        }
      },
      {
        name: 'Suspicious Bot',
        headers: {
          'User-Agent': 'python-requests/2.25.1'
          // Missing common browser headers
        }
      }
    ];

    for (const testCase of testCases) {
      try {
        const response = await axios.get(`${this.baseUrl}/api/rate-limit/test-fingerprint`, {
          headers: testCase.headers,
          timeout: 5000
        });

        console.log(`\n${testCase.name}:`);
        console.log(`  Fingerprint: ${response.data.data.fingerprint}`);
        console.log(`  Trust Score: ${response.data.data.analysis.trustScore}/10`);
        console.log(`  Browser: ${response.data.data.userAgent.browser}`);
        console.log(`  OS: ${response.data.data.userAgent.os}`);
        console.log(`  Device: ${response.data.data.userAgent.device}`);
        console.log(`  Suspicious Indicators: ${response.data.data.analysis.indicators.join(', ') || 'None'}`);

        this.testResults.push({
          timestamp: new Date().toISOString(),
          test: 'fingerprinting',
          case: testCase.name,
          result: response.data.data
        });
      } catch (error) {
        console.log(`\n${testCase.name}: ❌ Error - ${error.message}`);
      }
    }
  }

  /**
   * Simulate rate limiting attack
   */
  async simulateRateLimitAttack() {
    console.log('\n⚔️  Simulating Rate Limit Attack');
    console.log('-------------------------------');

    const attackTypes = [
      {
        name: 'Brute Force Login',
        endpoint: '/api/auth/login',
        method: 'POST',
        data: { login: 'admin', password: 'wrong' },
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      {
        name: 'Bot Attack',
        endpoint: '/api/auth/login',
        method: 'POST',
        data: { login: 'admin', password: 'wrong' },
        userAgent: 'AttackBot/1.0'
      },
      {
        name: 'Form Spam',
        endpoint: '/api/responses',
        method: 'POST',
        data: { responses: [{ question: 'spam', answer: 'spam' }] },
        userAgent: 'python-requests/2.25.1'
      }
    ];

    for (const attack of attackTypes) {
      console.log(`\n🎯 Testing ${attack.name}:`);
      let attempts = 0;
      let rateLimited = false;

      while (attempts < 10 && !rateLimited) {
        try {
          const startTime = Date.now();
          const response = await axios({
            method: attack.method.toLowerCase(),
            url: `${this.baseUrl}${attack.endpoint}`,
            data: attack.data,
            headers: {
              'User-Agent': attack.userAgent,
              'Content-Type': 'application/json'
            },
            timeout: 5000,
            validateStatus: () => true // Don't throw on HTTP errors
          });

          const duration = Date.now() - startTime;
          attempts++;

          if (response.status === 429) {
            console.log(`   Attempt ${attempts}: Rate limited after ${attempts} attempts (${duration}ms)`);
            rateLimited = true;
          } else {
            console.log(`   Attempt ${attempts}: ${response.status} (${duration}ms)`);
          }

          // Wait between attempts
          await this.sleep(1000);
        } catch (error) {
          console.log(`   Attempt ${attempts + 1}: Error - ${error.message}`);
          break;
        }
      }

      this.testResults.push({
        timestamp: new Date().toISOString(),
        test: 'rate-limit-attack',
        attack: attack.name,
        attempts,
        rateLimited
      });
    }
  }

  /**
   * Compare normal vs suspicious requests
   */
  async compareNormalVsSuspicious() {
    console.log('\n🔍 Comparing Normal vs Suspicious Requests');
    console.log('------------------------------------------');

    const normalRequest = {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
      }
    };

    const suspiciousRequest = {
      headers: {
        'User-Agent': 'bot-crawler-suspicious',
        'X-Forwarded-For': '10.0.0.1, 192.168.1.1',
        'X-Real-IP': '10.0.0.1'
      }
    };

    try {
      console.log('\n👤 Normal Request:');
      const normalResponse = await axios.post(`${this.baseUrl}/api/rate-limit/analyze-request`, {}, {
        headers: normalRequest.headers
      });

      const normalData = normalResponse.data.data;
      console.log(`  Trust Score: ${normalData.analysis.trustScore}/10`);
      console.log(`  Suspicious Count: ${normalData.analysis.suspiciousCount}`);
      console.log(`  Browser: ${normalData.deviceReport?.userAgent?.browser || 'unknown'}`);
      console.log(`  Indicators: ${normalData.analysis.indicators.join(', ') || 'None'}`);

      console.log('\n🤖 Suspicious Request:');
      const suspiciousResponse = await axios.post(`${this.baseUrl}/api/rate-limit/analyze-request`, {}, {
        headers: suspiciousRequest.headers
      });

      const suspiciousData = suspiciousResponse.data.data;
      console.log(`  Trust Score: ${suspiciousData.analysis.trustScore}/10`);
      console.log(`  Suspicious Count: ${suspiciousData.analysis.suspiciousCount}`);
      console.log(`  Browser: ${suspiciousData.deviceReport?.userAgent?.browser || 'unknown'}`);
      console.log(`  Indicators: ${suspiciousData.analysis.indicators.join(', ') || 'None'}`);

      console.log('\n📊 Comparison:');
      console.log(`  Trust Score Difference: ${normalData.analysis.trustScore - suspiciousData.analysis.trustScore}`);
      console.log(`  Normal would get ${normalData.analysis.trustScore >= 5 ? 'normal' : 'reduced'} rate limits`);
      console.log(`  Suspicious would get ${suspiciousData.analysis.trustScore >= 5 ? 'normal' : 'reduced'} rate limits`);

    } catch (error) {
      console.log(`❌ Error: ${error.message}`);
    }
  }

  /**
   * Test different user agents
   */
  async testDifferentUserAgents() {
    console.log('\n🌐 Testing Different User Agents');
    console.log('--------------------------------');

    const userAgents = [
      { name: 'Chrome 91', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36' },
      { name: 'Firefox 89', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0' },
      { name: 'Safari 14', ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15' },
      { name: 'Mobile Chrome', ua: 'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36' },
      { name: 'iPhone Safari', ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1' },
      { name: 'cURL', ua: 'curl/7.68.0' },
      { name: 'Python Requests', ua: 'python-requests/2.25.1' },
      { name: 'Empty', ua: '' }
    ];

    const results = [];

    for (const agent of userAgents) {
      try {
        const response = await axios.get(`${this.baseUrl}/api/rate-limit/test-fingerprint`, {
          headers: { 'User-Agent': agent.ua }
        });

        const data = response.data.data;
        results.push({
          name: agent.name,
          trustScore: data.analysis.trustScore,
          browser: data.userAgent.browser,
          os: data.userAgent.os,
          device: data.userAgent.device,
          suspicious: data.analysis.indicators.length
        });

        console.log(`${agent.name}: Trust=${data.analysis.trustScore}, Browser=${data.userAgent.browser}, Suspicious=${data.analysis.indicators.length}`);
      } catch (error) {
        console.log(`${agent.name}: Error - ${error.message}`);
      }
    }

    // Sort by trust score
    results.sort((a, b) => b.trustScore - a.trustScore);
    
    console.log('\n🏆 Trust Score Rankings:');
    results.forEach((result, index) => {
      console.log(`${index + 1}. ${result.name} (${result.trustScore}/10)`);
    });
  }

  /**
   * Benchmark fingerprinting performance
   */
  async benchmarkPerformance() {
    console.log('\n⚡ Benchmarking Fingerprinting Performance');
    console.log('----------------------------------------');

    const testCount = 100;
    const concurrentRequests = 10;

    console.log(`Testing ${testCount} requests with ${concurrentRequests} concurrent connections...`);

    const startTime = Date.now();
    const promises = [];

    for (let i = 0; i < testCount; i++) {
      const promise = axios.get(`${this.baseUrl}/api/rate-limit/test-fingerprint`, {
        headers: {
          'User-Agent': `TestClient-${i}`,
          'Accept-Language': 'en-US,en;q=0.9'
        },
        timeout: 10000
      }).then(response => ({
        success: true,
        duration: Date.now() - startTime
      })).catch(error => ({
        success: false,
        error: error.message
      }));

      promises.push(promise);

      // Control concurrency
      if (promises.length >= concurrentRequests) {
        await Promise.all(promises.splice(0, concurrentRequests));
      }
    }

    // Wait for remaining requests
    const results = await Promise.all(promises);
    const totalTime = Date.now() - startTime;

    const successful = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;
    const avgTime = totalTime / testCount;
    const requestsPerSecond = (testCount / totalTime) * 1000;

    console.log('\n📊 Performance Results:');
    console.log(`  Total Time: ${totalTime}ms`);
    console.log(`  Successful: ${successful}/${testCount}`);
    console.log(`  Failed: ${failed}/${testCount}`);
    console.log(`  Average per request: ${avgTime.toFixed(2)}ms`);
    console.log(`  Requests per second: ${requestsPerSecond.toFixed(2)}`);
  }

  /**
   * Monitor rate limit statistics
   */
  async monitorStatistics() {
    console.log('\n📊 Rate Limit Statistics Monitor');
    console.log('-------------------------------');

    try {
      const response = await axios.get(`${this.baseUrl}/api/rate-limit/dashboard`);
      const data = response.data.data;

      console.log('\n🔍 System Overview:');
      console.log(`  Cache Entries: ${data.overview.totalCacheEntries}`);
      console.log(`  Active Fingerprints: ${data.overview.activeFingerprints}`);
      console.log(`  Rate Limit Violations: ${data.overview.rateLimitViolations}`);
      console.log(`  Cache Hit Rate: ${data.overview.cacheHitRate}%`);

      console.log('\n🌐 Browser Distribution:');
      Object.entries(data.distribution.browsers).forEach(([browser, count]) => {
        console.log(`  ${browser}: ${count}`);
      });

      console.log('\n💻 OS Distribution:');
      Object.entries(data.distribution.operatingSystems).forEach(([os, count]) => {
        console.log(`  ${os}: ${count}`);
      });

      console.log('\n🔧 System Info:');
      console.log(`  Uptime: ${Math.floor(data.system.uptime / 60)} minutes`);
      console.log(`  Memory Usage: ${data.system.memoryUsage} MB`);
      console.log(`  Cache Size: ${data.system.cacheSize}`);

    } catch (error) {
      console.log(`❌ Error getting statistics: ${error.message}`);
    }
  }

  /**
   * Test specific auth endpoints
   */
  async testAuthEndpoints() {
    console.log('\n🔐 Testing Auth Endpoints Rate Limiting');
    console.log('--------------------------------------');

    const endpoints = [
      { path: '/api/auth/login', name: 'Login', data: { login: 'test', password: 'test' } },
      { path: '/api/auth/register', name: 'Registration', data: { username: 'test', email: 'test@test.com', password: 'test123' } },
      { path: '/api/responses', name: 'Form Submission', data: { responses: [{ question: 'test', answer: 'test' }] } }
    ];

    for (const endpoint of endpoints) {
      console.log(`\n🎯 Testing ${endpoint.name} (${endpoint.path})`);
      
      let attempts = 0;
      let rateLimited = false;
      const maxAttempts = 8;

      while (attempts < maxAttempts && !rateLimited) {
        try {
          const response = await axios.post(`${this.baseUrl}${endpoint.path}`, endpoint.data, {
            headers: {
              'User-Agent': 'Rate-Limit-Tester/1.0',
              'Content-Type': 'application/json'
            },
            timeout: 5000,
            validateStatus: () => true
          });

          attempts++;

          if (response.status === 429) {
            console.log(`  ⛔ Rate limited after ${attempts} attempts`);
            rateLimited = true;
          } else {
            console.log(`  Attempt ${attempts}: ${response.status}`);
          }

          await this.sleep(500);
        } catch (error) {
          console.log(`  ❌ Error on attempt ${attempts + 1}: ${error.message}`);
          break;
        }
      }

      if (!rateLimited && attempts >= maxAttempts) {
        console.log(`  ⚠️  No rate limiting detected after ${maxAttempts} attempts`);
      }
    }
  }

  /**
   * Export test results
   */
  async exportResults() {
    console.log('\n📄 Exporting Test Results');
    console.log('-------------------------');

    if (this.testResults.length === 0) {
      console.log('No test results to export. Run some tests first.');
      return;
    }

    const fs = require('fs');
    const filename = `rate-limit-test-results-${Date.now()}.json`;
    
    try {
      fs.writeFileSync(filename, JSON.stringify({
        metadata: {
          testDate: new Date().toISOString(),
          totalTests: this.testResults.length,
          baseUrl: this.baseUrl
        },
        results: this.testResults
      }, null, 2));

      console.log(`✅ Results exported to ${filename}`);
      console.log(`Total tests: ${this.testResults.length}`);
    } catch (error) {
      console.log(`❌ Failed to export results: ${error.message}`);
    }
  }

  /**
   * Helper methods
   */
  prompt(question) {
    return new Promise(resolve => {
      rl.question(question, answer => {
        resolve(answer);
      });
    });
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  cleanup() {
    rl.close();
  }
}

// Main execution
async function main() {
  const tester = new RateLimitTester();

  console.log('🚀 Enhanced Rate Limiting Tester');
  console.log(`Testing against: ${tester.baseUrl}`);

  try {
    await tester.showMenu();
  } catch (error) {
    console.error('❌ Fatal error:', error.message);
  } finally {
    tester.cleanup();
    process.exit(0);
  }
}

// Handle interrupts
process.on('SIGINT', () => {
  console.log('\n👋 Interrupted by user');
  process.exit(0);
});

// Run if executed directly
if (require.main === module) {
  main();
}

module.exports = RateLimitTester;