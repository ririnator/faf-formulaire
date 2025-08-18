const dns = require('dns').promises;
const SecureLogger = require('../utils/secureLogger');

/**
 * Comprehensive list of known disposable email domains
 * Updated regularly to prevent abuse through temporary email services
 */
const DISPOSABLE_DOMAINS = new Set([
  // Popular disposable email services
  '10minutemail.com',
  '10minutemail.net',
  '20minutemail.com',
  '2prong.com',
  '33mail.com',
  '3d-painting.com',
  '7tags.com',
  'airmail.cc',
  'anonbox.net',
  'anonymbox.com',
  'antichef.com',
  'antispam24.de',
  'armyspy.com',
  'bloggerzoom.com',
  'bobmail.info',
  'brefmail.com',
  'bumpymail.com',
  'cachedgmail.com',
  'chacuo.net',
  'cmail.net',
  'crazymailing.com',
  'cubiclink.com',
  'curryworld.de',
  'cust.in',
  'dacoolest.com',
  'deadaddress.com',
  'despam.it',
  'disposeamail.com',
  'disposableemailaddresses.com',
  'disposableinbox.com',
  'dispose.it',
  'dispostable.com',
  'dodgeit.com',
  'dodgit.com',
  'dontreg.com',
  'dontsendmespam.de',
  'duck2.co',
  'duckduckgo.com',
  'e4ward.com',
  'easytrashmail.com',
  'emailias.com',
  'emailsensei.com',
  'emailtemporario.com.br',
  'emailto.de',
  'emailxfer.com',
  'emkei.cz',
  'evopo.com',
  'explodemail.com',
  'fastmail.fm',
  'filzmail.com',
  'fixmail.org',
  'frapmail.com',
  'fudgerub.com',
  'fux0ringduh.com',
  'garbagemail.org',
  'gawab.com',
  'get-mail.cf',
  'getairmail.com',
  'getmails.eu',
  'ghosttexter.de',
  'girlsundertheinfluence.com',
  'gishpuppy.com',
  'grandmamail.com',
  'grandmasmail.com',
  'guerrillamail.biz',
  'guerrillamail.com',
  'guerrillamail.de',
  'guerrillamail.info',
  'guerrillamail.net',
  'guerrillamail.org',
  'guerrillamailblock.com',
  'haltospam.com',
  'hatespam.org',
  'hatredir.com',
  'hideme.be',
  'hidemail.de',
  'hidzz.com',
  'hmamail.com',
  'hochsitze.com',
  'hotpop.com',
  'hulapla.de',
  'ieatspam.eu',
  'ieatspam.info',
  'ihateyoualot.info',
  'ikbenspamvrij.nl',
  'imails.info',
  'inboxalias.com',
  'incognitomail.com',
  'incognitomail.net',
  'incognitomail.org',
  'insorg-mail.info',
  'instant-mail.de',
  'ipoo.org',
  'irish2me.com',
  'jetable.com',
  'jetable.fr.nf',
  'jetable.net',
  'jetable.org',
  'jnxjn.com',
  'jourrapide.com',
  'jsrsolutions.com',
  'kasmail.com',
  'klassmaster.com',
  'klzlk.com',
  'kook.ml',
  'kurzepost.de',
  'lawlita.com',
  'letthemeatspam.com',
  'lhsdv.com',
  'lifebyfood.com',
  'link2mail.net',
  'litedrop.com',
  'liveradio.tk',
  'loadby.us',
  'login-email.cf',
  'login-email.ga',
  'login-email.ml',
  'login-email.tk',
  'lol.ovpn.to',
  'lovemeleaveme.com',
  'lr78.com',
  'maboard.com',
  'mail-temporaire.fr',
  'mail.by',
  'mail.mezimages.net',
  'mail2rss.org',
  'mail333.com',
  'mail4trash.com',
  'mailbidon.com',
  'mailbiz.biz',
  'mailblocks.com',
  'mailbucket.org',
  'mailcatch.com',
  'maildrop.cc',
  'maildrop.cf',
  'maildrop.ga',
  'maildrop.gq',
  'maildrop.ml',
  'maildx.com',
  'maileater.com',
  'mailexpire.com',
  'mailfa.tk',
  'mailforspam.com',
  'mailfree.ga',
  'mailfree.gq',
  'mailfree.ml',
  'mailguard.me',
  'mailimate.com',
  'mailin8r.com',
  'mailinater.com',
  'mailinator.com',
  'mailinator.gq',
  'mailinator.net',
  'mailinator.org',
  'mailinator2.com',
  'mailincubator.com',
  'mailismagic.com',
  'mailme.gq',
  'mailme.ir',
  'mailme.lv',
  'mailme24.com',
  'mailmetrash.com',
  'mailmoat.com',
  'mailnator.com',
  'mailnesia.com',
  'mailnull.com',
  'mailpick.biz',
  'mailrock.biz',
  'mailscrap.com',
  'mailshell.com',
  'mailsiphon.com',
  'mailtemp.info',
  'mailtome.de',
  'mailtothis.com',
  'mailtrash.net',
  'mailtv.net',
  'mailtv.tv',
  'mailzilla.com',
  'mailzilla.org',
  'makemetheking.com',
  'manybrain.com',
  'mbx.cc',
  'mega.zik.dj',
  'meltmail.com',
  'messagebeamer.de',
  'mierdamail.com',
  'mintemail.com',
  'mjukglass.nu',
  'mobi.web.id',
  'moburl.com',
  'moncourrier.fr.nf',
  'monemail.fr.nf',
  'monmail.fr.nf',
  'monumentmail.com',
  'mt2009.com',
  'mt2014.com',
  'mypartyclip.de',
  'myphantomemail.com',
  'myspamless.com',
  'mytrashmail.com',
  'neomailbox.com',
  'nepwk.com',
  'nervmich.net',
  'nervtmich.net',
  'netmails.com',
  'netmails.net',
  'netzidiot.de',
  'neverbox.com',
  'nice-4u.com',
  'nincsmail.com',
  'nincsmail.hu',
  'nnh.com',
  'no-spam.ws',
  'noblepioneer.com',
  'nomail.xl.cx',
  'nomail2me.com',
  'nomorespamemails.com',
  'nonspam.eu',
  'nonspammer.de',
  'noref.in',
  'nospam.ze.tc',
  'nospam4.us',
  'nospamfor.us',
  'nospammail.net',
  'notmailinator.com',
  'nowmymail.com',
  'nullbox.info',
  'nurfuerspam.de',
  'nus.edu.sg',
  'objectmail.com',
  'obobbo.com',
  'odnorazovoe.ru',
  'oneoffemail.com',
  'onewaymail.com',
  'ordinaryamerican.net',
  'otherinbox.com',
  'ovpn.to',
  'owlpic.com',
  'pjkltd.com',
  'pookmail.com',
  'proxymail.eu',
  'prtnx.com',
  'punkass.com',
  'putthisinyourspamdatabase.com',
  'quickinbox.com',
  'rcpt.at',
  'reallymymail.com',
  'recode.me',
  'reconmail.com',
  'recursor.net',
  'regbypass.com',
  'regbypass.comsafe-mail.net',
  'reliable-mail.com',
  'rhyta.com',
  'rklips.com',
  'rmqkr.net',
  'rppkn.com',
  'rtrtr.com',
  'safe-mail.net',
  'safersignup.de',
  'sandelf.de',
  'sendspamhere.de',
  'senseless-entertainment.com',
  'sharklasers.com',
  'shieldedmail.com',
  'shitmail.me',
  'shitware.nl',
  'shmeriously.com',
  'shortmail.net',
  'sibmail.com',
  'skeefmail.com',
  'smashmail.de',
  'smellfear.com',
  'snakemail.com',
  'sneakemail.com',
  'snkmail.com',
  'sofimail.com',
  'sofort-mail.de',
  'sogetthis.com',
  'soodonims.com',
  'spam.la',
  'spam4.me',
  'spamavert.com',
  'spambob.com',
  'spambob.net',
  'spambob.org',
  'spambog.com',
  'spambog.de',
  'spambog.net',
  'spambog.ru',
  'spambox.info',
  'spambox.irishspringtours.com',
  'spambox.us',
  'spamcannon.com',
  'spamcannon.net',
  'spamcero.com',
  'spamcon.org',
  'spamcorptastic.com',
  'spamcowboy.com',
  'spamcowboy.net',
  'spamcowboy.org',
  'spamday.com',
  'spamdecoy.net',
  'spamex.com',
  'spamfight.org',
  'spamfighter.cf',
  'spamfighter.ga',
  'spamfighter.gq',
  'spamfighter.ml',
  'spamfighter.tk',
  'spamfree24.com',
  'spamfree24.de',
  'spamfree24.eu',
  'spamfree24.net',
  'spamfree24.org',
  'spamgoes.com',
  'spamgourmet.com',
  'spamgourmet.net',
  'spamgourmet.org',
  'spamherelots.com',
  'spamhereplease.com',
  'spamhole.com',
  'spami.spam.co.za',
  'spaminator.de',
  'spamkill.info',
  'spaml.com',
  'spaml.de',
  'spammotel.com',
  'spamobox.com',
  'spamoff.de',
  'spamsalad.in',
  'spamspot.com',
  'spamstack.net',
  'spamthis.co.uk',
  'spamthisplease.com',
  'spamtrail.com',
  'spamtroll.net',
  'speed.1s.fr',
  'squizzy.de',
  'ssoia.com',
  'startkeys.com',
  'supergreatmail.com',
  'supermailer.jp',
  'superrito.com',
  'superstachel.de',
  'suremail.info',
  'talkinator.com',
  'teewars.org',
  'teleworm.com',
  'teleworm.us',
  'temp-mail.de',
  'temp-mail.org',
  'temp-mail.ru',
  'tempalias.com',
  'tempe-mail.com',
  'tempemail.biz',
  'tempemail.com',
  'tempemail.net',
  'tempemail.org',
  'tempinbox.co.uk',
  'tempinbox.com',
  'tempmail.eu',
  'tempmail2.com',
  'tempmaildemo.com',
  'tempmailer.com',
  'tempmailer.de',
  'tempmailaddress.com',
  'tempomail.fr',
  'temporarily.de',
  'temporarioemail.com.br',
  'temporaryemail.net',
  'temporaryforwarding.com',
  'temporaryinbox.com',
  'temporarymailaddress.com',
  'tempthe.net',
  'thankyou2010.com',
  'thc.st',
  'thelimestones.com',
  'thisisnotmyrealemail.com',
  'thismail.net',
  'throwam.com',
  'throwawayemailaddresses.com',
  'tilien.com',
  'tittbit.in',
  'tmail.ws',
  'tmailinator.com',
  'toiea.com',
  'toomail.biz',
  'topranklist.de',
  'tormail.net',
  'tormail.org',
  'tradermail.info',
  'trash-amil.com',
  'trash-mail.at',
  'trash-mail.cf',
  'trash-mail.com',
  'trash-mail.de',
  'trash-mail.ga',
  'trash-mail.gq',
  'trash-mail.ml',
  'trash-mail.tk',
  'trash2009.com',
  'trash2010.com',
  'trash2011.com',
  'trashdevil.com',
  'trashdevil.de',
  'trashemail.de',
  'trashemailaddress.com',
  'trashmail.at',
  'trashmail.com',
  'trashmail.de',
  'trashmail.me',
  'trashmail.net',
  'trashmail.org',
  'trashmail.ws',
  'trashmailer.com',
  'trashymail.com',
  'trashymail.net',
  'trillianpro.com',
  'turual.com',
  'twinmail.de',
  'twoweirdtricks.com',
  'tyldd.com',
  'uggsrock.com',
  'umail.net',
  'upliftnow.com',
  'uplipht.com',
  'venompen.com',
  'veryrealemail.com',
  'viditag.com',
  'viralplays.com',
  'vpn.st',
  'vstromeinhanging.nl',
  'wegwerfadresse.de',
  'wegwerfemail.com',
  'wegwerfemail.de',
  'wegwerfmail.de',
  'wegwerfmail.info',
  'wegwerfmail.net',
  'wegwerfmail.org',
  'wh4f.org',
  'whopy.com',
  'willselfdestruct.com',
  'winemaven.info',
  'wronghead.com',
  'wuzup.net',
  'wuzupmail.net',
  'xents.com',
  'xmaily.com',
  'xoxy.net',
  'yapped.net',
  'yeah.net',
  'yep.it',
  'yogamaven.com',
  'yopmail.com',
  'yopmail.fr',
  'yopmail.net',
  'yourdomain.com',
  'ypmail.webredirect.org',
  'yuurok.com',
  'zehnminuten.de',
  'zehnminutenmail.de',
  'zetmail.com',
  'zippymail.info',
  'zoemail.net',
  'zoemail.org',
  'zombie-hive.com',
  'zomg.info'
]);

/**
 * Suspicious domain patterns that often indicate disposable or fake emails
 */
const SUSPICIOUS_PATTERNS = [
  /^\d+mail/,           // Numeric prefixes like "10mail", "20mail"
  /temp.*mail/,         // "tempmail", "temporarymail", etc.
  /disposable/,         // "disposable" anywhere in domain
  /throw.*away/,        // "throwaway" patterns
  /trash.*mail/,        // "trashmail" patterns
  /spam.*mail/,         // "spammail" patterns
  /fake.*mail/,         // "fakemail" patterns
  /test.*mail/,         // "testmail" patterns
  /junk.*mail/,         // "junkmail" patterns
  /no.*spam/,           // "nospam" patterns
  /guerrilla/,          // "guerrilla" mail services
  /mailinator/,         // Mailinator variants
  /\d{1,2}min/,         // Time-based like "10min", "20min"
  /^[a-z]{1,3}\.[a-z]{1,3}$/,  // Very short domains like "a.co"
];

/**
 * Configuration for email domain validation
 */
class EmailDomainConfig {
  constructor() {
    this.allowedDomains = new Set(process.env.EMAIL_DOMAIN_WHITELIST?.split(',').filter(Boolean) || []);
    this.blockedDomains = new Set(process.env.EMAIL_DOMAIN_BLACKLIST?.split(',').filter(Boolean) || []);
    this.enableMXValidation = process.env.EMAIL_MX_VALIDATION !== 'false';
    this.enableDisposableCheck = process.env.EMAIL_DISPOSABLE_CHECK !== 'false';
    this.enableSuspiciousPatternCheck = process.env.EMAIL_SUSPICIOUS_PATTERN_CHECK !== 'false';
    this.logBlockedAttempts = process.env.EMAIL_LOG_BLOCKED !== 'false';
  }

  /**
   * Check if domain is explicitly allowed
   */
  isDomainAllowed(domain) {
    return this.allowedDomains.has(domain.toLowerCase());
  }

  /**
   * Check if domain is explicitly blocked
   */
  isDomainBlocked(domain) {
    return this.blockedDomains.has(domain.toLowerCase());
  }

  /**
   * Add domain to whitelist
   */
  allowDomain(domain) {
    this.allowedDomains.add(domain.toLowerCase());
  }

  /**
   * Add domain to blacklist
   */
  blockDomain(domain) {
    this.blockedDomains.add(domain.toLowerCase());
  }

  /**
   * Remove domain from whitelist
   */
  disallowDomain(domain) {
    this.allowedDomains.delete(domain.toLowerCase());
  }

  /**
   * Remove domain from blacklist
   */
  unblockDomain(domain) {
    this.blockedDomains.delete(domain.toLowerCase());
  }
}

const emailConfig = new EmailDomainConfig();

/**
 * Sanitize and validate input to prevent injection attacks
 */
function sanitizeInput(input) {
  if (!input || typeof input !== 'string') {
    return null;
  }
  
  if (input === '') {
    return null; // Empty string returns null for consistency
  }
  
  // Remove null bytes and control characters (including Unicode invisible chars)
  let sanitized = input.replace(/[\x00-\x1F\x7F\u0000-\u001F\u007F-\u009F\u2028\u2029\uFEFF\u200B-\u200F\u202A-\u202E\u2060-\u206F]/g, '');
  
  // Remove SQL injection patterns
  const sqlPatterns = [
    /['"`;\-\-]/g,           // SQL metacharacters
    /(union|select|insert|update|delete|drop|create|alter|exec|execute)/gi,
    /(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/gi,
    /\s+(or|and)\s+['"]?[\w\s]*['"]?\s*=\s*['"]?[\w\s]*['"]?/gi
  ];
  
  // Remove NoSQL injection patterns
  const noSqlPatterns = [
    /\$where/gi,
    /\$regex/gi,
    /\$ne/gi,
    /\$gt/gi,
    /\$lt/gi,
    /\$in/gi,
    /\$nin/gi,
    /\$exists/gi,
    /\$or/gi,
    /\$and/gi
  ];
  
  // Remove XSS patterns
  const xssPatterns = [
    /<script[^>]*>.*?<\/script>/gi,
    /<iframe[^>]*>.*?<\/iframe>/gi,
    /<object[^>]*>.*?<\/object>/gi,
    /<embed[^>]*>.*?<\/embed>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<[^>]*>/g  // Remove all HTML tags
  ];
  
  // Remove command injection patterns
  const cmdPatterns = [
    /[;&|`$(){}\[\]]/g,      // Shell metacharacters
    /(whoami|ls|cat|echo|pwd|id|uname)/gi,
    /\$\([^)]*\)/g,          // Command substitution
    /`[^`]*`/g               // Backtick execution
  ];
  
  // Apply all sanitization patterns
  [...sqlPatterns, ...noSqlPatterns, ...xssPatterns, ...cmdPatterns].forEach(pattern => {
    sanitized = sanitized.replace(pattern, '');
  });
  
  return sanitized.trim();
}

/**
 * Validate email format with strict security checks
 */
function validateEmailFormat(email) {
  if (!email || typeof email !== 'string') {
    return false;
  }
  
  // Length limits to prevent buffer overflow
  if (email.length > 320) { // RFC 5321 limit
    return false;
  }
  
  const sanitized = sanitizeInput(email);
  if (!sanitized || sanitized !== email.trim()) {
    return false; // Injection attempt detected
  }
  
  // RFC 5322 compliant regex with additional security constraints
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  
  if (!emailRegex.test(sanitized)) {
    return false;
  }
  
  // Additional security checks
  const [localPart, domainPart] = sanitized.split('@');
  
  // Local part validation
  if (localPart.length > 64) { // RFC 5321 limit
    return false;
  }
  
  // Domain part validation
  if (domainPart.length > 253) { // RFC 5321 limit
    return false;
  }
  
  // Check for consecutive dots
  if (domainPart.includes('..')) {
    return false;
  }
  
  // Check for invalid characters that might bypass filters
  const invalidChars = /[\x00-\x1F\x7F\s"'<>&(){}\[\]$`|;]/;
  if (invalidChars.test(sanitized)) {
    return false;
  }
  
  return true;
}

/**
 * Extract domain from email address with security validation
 */
function extractDomain(email) {
  if (!validateEmailFormat(email)) {
    return null;
  }
  
  const sanitized = sanitizeInput(email);
  if (!sanitized) {
    return null;
  }
  
  const trimmed = sanitized.toLowerCase();
  const parts = trimmed.split('@');
  
  if (parts.length !== 2) {
    return null;
  }
  
  const domain = parts[1];
  
  // Additional domain validation
  if (domain.length < 3 || domain.length > 253) {
    return null;
  }
  
  // Check for valid domain format
  const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!domainRegex.test(domain)) {
    return null;
  }
  
  return domain;
}

/**
 * Check if domain matches suspicious patterns
 */
function matchesSuspiciousPattern(domain) {
  return SUSPICIOUS_PATTERNS.some(pattern => pattern.test(domain));
}

/**
 * Validate domain against MX records
 */
async function validateMXRecord(domain) {
  try {
    const mxRecords = await dns.resolveMx(domain);
    return mxRecords && mxRecords.length > 0;
  } catch (error) {
    // Domain doesn't exist or has no MX record
    return false;
  }
}

/**
 * Check if domain exists (has any DNS records)
 */
async function validateDomainExists(domain) {
  try {
    // Try to resolve A record
    await dns.resolve4(domain);
    return true;
  } catch (error) {
    try {
      // Try to resolve AAAA record
      await dns.resolve6(domain);
      return true;
    } catch (error2) {
      try {
        // Try to resolve MX record
        await dns.resolveMx(domain);
        return true;
      } catch (error3) {
        // Domain doesn't exist
        return false;
      }
    }
  }
}

/**
 * Comprehensive email domain validation with enhanced security
 */
async function validateEmailDomain(email, options = {}) {
  const {
    skipMXValidation = false,
    skipDisposableCheck = false,
    skipSuspiciousPatternCheck = false,
    skipDomainExistenceCheck = false
  } = options;

  // First, validate the input for injection attempts
  if (!email || typeof email !== 'string') {
    return {
      isValid: false,
      reason: 'INVALID_INPUT',
      message: 'Email invalide'
    };
  }
  
  // Check for injection patterns before processing
  const originalEmail = email;
  const sanitizedEmail = sanitizeInput(email);
  
  if (!sanitizedEmail || sanitizedEmail !== originalEmail.trim()) {
    SecureLogger.logSecurityEvent('email_injection_attempt', {
      originalEmail: originalEmail.substring(0, 50) + '...', // Truncate for logging
      sanitizedEmail: sanitizedEmail,
      timestamp: new Date().toISOString()
    });
    
    return {
      isValid: false,
      reason: 'SECURITY_VIOLATION',
      message: 'Format d\'email invalide'
    };
  }
  
  // Validate email format with security checks
  if (!validateEmailFormat(sanitizedEmail)) {
    return {
      isValid: false,
      reason: 'INVALID_EMAIL_FORMAT',
      message: 'Format d\'email invalide'
    };
  }

  const domain = extractDomain(sanitizedEmail);
  
  if (!domain) {
    return {
      isValid: false,
      reason: 'INVALID_EMAIL_FORMAT',
      message: 'Format d\'email invalide'
    };
  }

  // Check whitelist first (if domain is whitelisted, allow it)
  if (emailConfig.isDomainAllowed(domain)) {
    return {
      isValid: true,
      reason: 'WHITELISTED',
      message: 'Domaine autorisé'
    };
  }

  // Check for disposable email domains first (more specific than blacklist)
  if (!skipDisposableCheck && emailConfig.enableDisposableCheck && DISPOSABLE_DOMAINS.has(domain)) {
    return {
      isValid: false,
      reason: 'DISPOSABLE_DOMAIN',
      message: 'Les adresses email temporaires ne sont pas autorisées'
    };
  }

  // Check blacklist (for custom blocked domains)
  if (emailConfig.isDomainBlocked(domain) && !DISPOSABLE_DOMAINS.has(domain)) {
    return {
      isValid: false,
      reason: 'BLACKLISTED',
      message: 'Domaine bloqué'
    };
  }

  // Check for suspicious patterns
  if (!skipSuspiciousPatternCheck && emailConfig.enableSuspiciousPatternCheck && matchesSuspiciousPattern(domain)) {
    return {
      isValid: false,
      reason: 'SUSPICIOUS_PATTERN',
      message: 'Domaine suspect détecté'
    };
  }

  // Check domain existence
  if (!skipDomainExistenceCheck) {
    const domainExists = await validateDomainExists(domain);
    if (!domainExists) {
      return {
        isValid: false,
        reason: 'DOMAIN_NOT_EXISTS',
        message: 'Le domaine n\'existe pas'
      };
    }
  }

  // Check MX records (email capability)
  if (!skipMXValidation && emailConfig.enableMXValidation) {
    const hasMXRecord = await validateMXRecord(domain);
    if (!hasMXRecord) {
      return {
        isValid: false,
        reason: 'NO_MX_RECORD',
        message: 'Le domaine ne peut pas recevoir d\'emails'
      };
    }
  }

  return {
    isValid: true,
    reason: 'VALID',
    message: 'Email valide'
  };
}

/**
 * Express middleware for email domain validation
 */
function createEmailDomainMiddleware(options = {}) {
  const {
    emailField = 'email',
    skipValidationFor = [],
    logBlocked = true
  } = options;

  return async (req, res, next) => {
    try {
      const email = req.body[emailField];
      
      if (!email) {
        return next(); // Let other validation handle missing email
      }
      
      // Enhanced security check for request tampering
      if (typeof email !== 'string') {
        SecureLogger.logSecurityEvent('email_type_tampering', {
          emailType: typeof email,
          emailValue: String(email).substring(0, 50),
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          timestamp: new Date().toISOString()
        });
        
        return res.status(400).json({
          error: 'Format d\'email invalide',
          message: 'Type de données invalide',
          code: 'INVALID_DATA_TYPE'
        });
      }
      
      // Check for obvious injection attempts before validation
      const injectionPatterns = [
        /[\x00-\x1F\x7F]/,  // Control characters
        /['"`;]/,           // SQL injection chars
        /\$\w+/,            // NoSQL operators
        /<[^>]*>/,          // HTML/XML tags
        /javascript:/i,     // XSS protocols
        /[;&|`$()]/         // Command injection
      ];
      
      const hasInjectionAttempt = injectionPatterns.some(pattern => pattern.test(email));
      if (hasInjectionAttempt) {
        SecureLogger.logSecurityEvent('email_injection_blocked', {
          email: email.substring(0, 20) + '***',
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          path: req.path,
          timestamp: new Date().toISOString()
        });
        
        return res.status(400).json({
          error: 'Email non autorisé',
          message: 'Format d\'email invalide',
          code: 'SECURITY_VIOLATION'
        });
      }

      // Skip validation for specific routes if configured
      if (skipValidationFor.includes(req.path)) {
        return next();
      }

      // Rate limiting for suspicious requests
      const clientIP = req.ip;
      const now = Date.now();
      const rateLimitKey = `email_validation_${clientIP}`;
      
      // Simple in-memory rate limiting (production should use Redis)
      if (!req.app.locals.emailValidationAttempts) {
        req.app.locals.emailValidationAttempts = new Map();
      }
      
      const attempts = req.app.locals.emailValidationAttempts.get(rateLimitKey) || [];
      const recentAttempts = attempts.filter(timestamp => now - timestamp < 60000); // 1 minute window
      
      if (recentAttempts.length >= 10) { // Max 10 attempts per minute
        SecureLogger.logSecurityEvent('email_validation_rate_limit', {
          ip: clientIP,
          attempts: recentAttempts.length,
          timeWindow: '1m',
          timestamp: new Date().toISOString()
        });
        
        return res.status(429).json({
          error: 'Trop de tentatives',
          message: 'Veuillez réessayer dans quelques minutes',
          code: 'RATE_LIMITED'
        });
      }
      
      // Record this attempt
      recentAttempts.push(now);
      req.app.locals.emailValidationAttempts.set(rateLimitKey, recentAttempts);
      
      const validation = await validateEmailDomain(email, options);
      
      if (!validation.isValid) {
        // Log blocked attempt for security monitoring
        if (logBlocked && emailConfig.logBlockedAttempts) {
          const domain = extractDomain(email);
          SecureLogger.logSecurityEvent('email_domain_blocked', {
            email: email.replace(/(.{1,3}).*(@.*)/, '$1***$2'), // Partially obscure email
            domain: domain,
            reason: validation.reason,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            path: req.path,
            timestamp: new Date().toISOString()
          });
        }

        return res.status(400).json({
          error: 'Email non autorisé',
          message: validation.message,
          code: validation.reason
        });
      }

      next();
    } catch (error) {
      SecureLogger.logError('Email domain validation failed', error);
      
      // In case of validation error, allow the request to proceed
      // to avoid blocking legitimate users due to infrastructure issues
      next();
    }
  };
}

/**
 * Utility function to check if an email domain is disposable
 */
function isDisposableEmail(email) {
  const domain = extractDomain(email);
  return domain && DISPOSABLE_DOMAINS.has(domain);
}

/**
 * Get statistics about blocked domains
 */
function getDomainBlockingStats() {
  return {
    disposableDomainsCount: DISPOSABLE_DOMAINS.size,
    suspiciousPatternsCount: SUSPICIOUS_PATTERNS.length,
    whitelistedDomainsCount: emailConfig.allowedDomains.size,
    blacklistedDomainsCount: emailConfig.blockedDomains.size,
    config: {
      enableMXValidation: emailConfig.enableMXValidation,
      enableDisposableCheck: emailConfig.enableDisposableCheck,
      enableSuspiciousPatternCheck: emailConfig.enableSuspiciousPatternCheck,
      logBlockedAttempts: emailConfig.logBlockedAttempts
    }
  };
}

module.exports = {
  validateEmailDomain,
  createEmailDomainMiddleware,
  isDisposableEmail,
  extractDomain,
  sanitizeInput,
  validateEmailFormat,
  EmailDomainConfig,
  emailConfig,
  getDomainBlockingStats,
  DISPOSABLE_DOMAINS,
  SUSPICIOUS_PATTERNS
};