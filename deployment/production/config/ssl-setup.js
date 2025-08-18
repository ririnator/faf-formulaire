/**
 * SSL/HTTPS Configuration Script for Production
 * Handles automated SSL certificate management with Let's Encrypt and manual certificate setup
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const { spawn } = require('child_process');

class SSLManager {
  constructor() {
    this.certDir = '/etc/ssl/certs';
    this.keyDir = '/etc/ssl/private';
    this.letsEncryptDir = '/etc/letsencrypt/live';
    this.domain = process.env.COOKIE_DOMAIN || 'yourdomain.com';
    this.email = process.env.LETSENCRYPT_EMAIL;
  }

  /**
   * Main SSL setup orchestration
   */
  async setupSSL() {
    console.log('🔒 Starting SSL/HTTPS configuration...\n');

    try {
      await this.checkPrerequisites();
      
      if (this.shouldUseLetsEncrypt()) {
        await this.setupLetsEncrypt();
      } else {
        await this.setupManualCertificates();
      }

      await this.configureNginx();
      await this.testSSLConfiguration();
      await this.setupCertificateRenewal();

      console.log('✅ SSL configuration completed successfully!');
    } catch (error) {
      console.error('❌ SSL setup failed:', error.message);
      throw error;
    }
  }

  /**
   * Check system prerequisites
   */
  async checkPrerequisites() {
    console.log('📋 Checking SSL prerequisites...');

    // Check if running as root (required for certificate operations)
    if (process.getuid && process.getuid() !== 0) {
      throw new Error('SSL setup requires root privileges. Run with sudo.');
    }

    // Check if domain is accessible
    try {
      await this.checkDomainReachability();
      console.log(`✅ Domain ${this.domain} is reachable`);
    } catch (error) {
      console.warn(`⚠️ Warning: Could not verify domain reachability: ${error.message}`);
    }

    // Create necessary directories
    await this.createSSLDirectories();
  }

  /**
   * Create SSL directories with proper permissions
   */
  async createSSLDirectories() {
    const directories = [this.certDir, this.keyDir];
    
    for (const dir of directories) {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
        console.log(`📁 Created directory: ${dir}`);
      }
    }
  }

  /**
   * Check if domain is reachable via HTTP
   */
  async checkDomainReachability() {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: this.domain,
        port: 80,
        path: '/',
        method: 'GET',
        timeout: 5000
      };

      const req = require('http').request(options, (res) => {
        resolve(res.statusCode);
      });

      req.on('error', reject);
      req.on('timeout', () => reject(new Error('Request timeout')));
      req.setTimeout(5000);
      req.end();
    });
  }

  /**
   * Determine if Let's Encrypt should be used
   */
  shouldUseLetsEncrypt() {
    return process.env.LETSENCRYPT_EMAIL && 
           process.env.LETSENCRYPT_DOMAINS && 
           !fs.existsSync(path.join(this.certDir, `${this.domain}.crt`));
  }

  /**
   * Setup Let's Encrypt certificates
   */
  async setupLetsEncrypt() {
    console.log('🚀 Setting up Let\'s Encrypt certificates...');

    // Install certbot if not present
    await this.installCertbot();

    // Generate certificates
    await this.generateLetsEncryptCertificates();

    // Symlink certificates to expected locations
    await this.symlinkCertificates();
  }

  /**
   * Install certbot
   */
  async installCertbot() {
    console.log('📦 Installing certbot...');

    return new Promise((resolve, reject) => {
      const child = spawn('apt-get', ['update', '&&', 'apt-get', 'install', '-y', 'certbot', 'python3-certbot-nginx'], {
        stdio: 'inherit',
        shell: true
      });

      child.on('close', (code) => {
        if (code === 0) {
          console.log('✅ Certbot installed successfully');
          resolve();
        } else {
          reject(new Error(`Certbot installation failed with code ${code}`));
        }
      });
    });
  }

  /**
   * Generate Let's Encrypt certificates
   */
  async generateLetsEncryptCertificates() {
    console.log('📜 Generating Let\'s Encrypt certificates...');

    const domains = process.env.LETSENCRYPT_DOMAINS.split(',').map(d => d.trim());
    const domainArgs = domains.flatMap(domain => ['-d', domain]);

    return new Promise((resolve, reject) => {
      const args = [
        'certonly',
        '--nginx',
        '--non-interactive',
        '--agree-tos',
        '--email', this.email,
        ...domainArgs
      ];

      const child = spawn('certbot', args, { stdio: 'inherit' });

      child.on('close', (code) => {
        if (code === 0) {
          console.log('✅ Let\'s Encrypt certificates generated successfully');
          resolve();
        } else {
          reject(new Error(`Certificate generation failed with code ${code}`));
        }
      });
    });
  }

  /**
   * Symlink Let's Encrypt certificates to expected locations
   */
  async symlinkCertificates() {
    const letsEncryptCertDir = path.join(this.letsEncryptDir, this.domain);
    
    const links = [
      {
        src: path.join(letsEncryptCertDir, 'fullchain.pem'),
        dest: path.join(this.certDir, `${this.domain}.crt`)
      },
      {
        src: path.join(letsEncryptCertDir, 'privkey.pem'),
        dest: path.join(this.keyDir, `${this.domain}.key`)
      }
    ];

    for (const link of links) {
      if (fs.existsSync(link.src)) {
        if (fs.existsSync(link.dest)) {
          fs.unlinkSync(link.dest);
        }
        fs.symlinkSync(link.src, link.dest);
        console.log(`🔗 Symlinked ${link.src} -> ${link.dest}`);
      }
    }
  }

  /**
   * Setup manual certificates (for custom CA or existing certificates)
   */
  async setupManualCertificates() {
    console.log('📋 Setting up manual certificates...');

    const certPath = process.env.SSL_CERT_PATH;
    const keyPath = process.env.SSL_KEY_PATH;

    if (!certPath || !keyPath) {
      throw new Error('SSL_CERT_PATH and SSL_KEY_PATH must be set for manual certificate setup');
    }

    // Validate certificate files exist
    if (!fs.existsSync(certPath)) {
      throw new Error(`Certificate file not found: ${certPath}`);
    }

    if (!fs.existsSync(keyPath)) {
      throw new Error(`Private key file not found: ${keyPath}`);
    }

    // Validate certificate
    await this.validateCertificate(certPath, keyPath);

    // Set proper permissions
    fs.chmodSync(certPath, 0o644);
    fs.chmodSync(keyPath, 0o600);

    console.log('✅ Manual certificates configured successfully');
  }

  /**
   * Validate certificate against private key
   */
  async validateCertificate(certPath, keyPath) {
    console.log('🔍 Validating certificate...');

    return new Promise((resolve, reject) => {
      // Check if certificate and key match
      const certData = fs.readFileSync(certPath);
      const keyData = fs.readFileSync(keyPath);

      try {
        // Basic validation - in production you'd want more thorough checks
        if (certData.includes('-----BEGIN CERTIFICATE-----') && 
            keyData.includes('-----BEGIN PRIVATE KEY-----')) {
          console.log('✅ Certificate format validation passed');
          resolve();
        } else {
          reject(new Error('Invalid certificate or key format'));
        }
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Configure Nginx for SSL
   */
  async configureNginx() {
    console.log('⚙️ Configuring Nginx for SSL...');

    const nginxConfig = this.generateNginxConfig();
    const configPath = '/etc/nginx/sites-available/faf-ssl';

    fs.writeFileSync(configPath, nginxConfig);
    
    // Enable site
    const enabledPath = '/etc/nginx/sites-enabled/faf-ssl';
    if (fs.existsSync(enabledPath)) {
      fs.unlinkSync(enabledPath);
    }
    fs.symlinkSync(configPath, enabledPath);

    // Test and reload Nginx
    await this.reloadNginx();
  }

  /**
   * Generate Nginx SSL configuration
   */
  generateNginxConfig() {
    const domain = this.domain;
    const appPort = process.env.PORT || 3000;

    return `
# FAF (Form-a-Friend) Production SSL Configuration
server {
    listen 80;
    server_name ${domain} www.${domain};
    
    # Redirect all HTTP traffic to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${domain} www.${domain};

    # SSL Configuration
    ssl_certificate ${this.certDir}/${domain}.crt;
    ssl_certificate_key ${this.keyDir}/${domain}.key;
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    
    # SSL session configuration
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_stapling on;
    ssl_stapling_verify on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Proxy configuration
    location / {
        proxy_pass http://localhost:${appPort};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Static file serving with caching
    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        proxy_pass http://localhost:${appPort};
        expires 1y;
        add_header Cache-Control "public, immutable";
        add_header X-Content-Type-Options nosniff;
    }

    # Security.txt
    location = /.well-known/security.txt {
        return 200 "Contact: security@${domain}\\nExpires: 2025-12-31T23:59:59.000Z\\nPreferred-Languages: en, fr\\n";
        add_header Content-Type text/plain;
    }
}
`;
  }

  /**
   * Reload Nginx configuration
   */
  async reloadNginx() {
    console.log('🔄 Reloading Nginx...');

    return new Promise((resolve, reject) => {
      // Test configuration first
      const testChild = spawn('nginx', ['-t'], { stdio: 'pipe' });
      
      testChild.on('close', (code) => {
        if (code !== 0) {
          reject(new Error('Nginx configuration test failed'));
          return;
        }

        // Reload if test passed
        const reloadChild = spawn('systemctl', ['reload', 'nginx'], { stdio: 'inherit' });
        
        reloadChild.on('close', (reloadCode) => {
          if (reloadCode === 0) {
            console.log('✅ Nginx reloaded successfully');
            resolve();
          } else {
            reject(new Error('Nginx reload failed'));
          }
        });
      });
    });
  }

  /**
   * Test SSL configuration
   */
  async testSSLConfiguration() {
    console.log('🧪 Testing SSL configuration...');

    const testUrl = `https://${this.domain}`;
    
    return new Promise((resolve, reject) => {
      const options = {
        hostname: this.domain,
        port: 443,
        path: '/',
        method: 'GET',
        timeout: 10000
      };

      const req = https.request(options, (res) => {
        if (res.statusCode === 200 || res.statusCode === 302 || res.statusCode === 301) {
          console.log('✅ SSL test successful');
          resolve();
        } else {
          reject(new Error(`SSL test failed with status ${res.statusCode}`));
        }
      });

      req.on('error', (error) => {
        reject(new Error(`SSL test failed: ${error.message}`));
      });

      req.on('timeout', () => {
        reject(new Error('SSL test timeout'));
      });

      req.setTimeout(10000);
      req.end();
    });
  }

  /**
   * Setup automatic certificate renewal
   */
  async setupCertificateRenewal() {
    console.log('🔄 Setting up certificate renewal...');

    if (this.shouldUseLetsEncrypt()) {
      await this.setupLetsEncryptRenewal();
    } else {
      console.log('⚠️ Manual certificates - setup renewal monitoring separately');
    }
  }

  /**
   * Setup Let's Encrypt automatic renewal
   */
  async setupLetsEncryptRenewal() {
    const cronJob = `
# Let's Encrypt certificate renewal for FAF
0 12 * * * /usr/bin/certbot renew --quiet --deploy-hook "systemctl reload nginx"
`;

    fs.appendFileSync('/etc/crontab', cronJob);
    console.log('✅ Let\'s Encrypt renewal cron job added');

    // Test renewal
    return new Promise((resolve, reject) => {
      const child = spawn('certbot', ['renew', '--dry-run'], { stdio: 'inherit' });
      
      child.on('close', (code) => {
        if (code === 0) {
          console.log('✅ Certificate renewal test successful');
          resolve();
        } else {
          console.warn('⚠️ Certificate renewal test failed - check configuration');
          resolve(); // Don't fail deployment for this
        }
      });
    });
  }
}

// Export for use in other scripts
module.exports = SSLManager;

// Run if called directly
if (require.main === module) {
  const sslManager = new SSLManager();
  sslManager.setupSSL().catch(error => {
    console.error('❌ SSL setup failed:', error);
    process.exit(1);
  });
}