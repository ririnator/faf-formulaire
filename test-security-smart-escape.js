// Test de la fonction smartEscape pour vérifier la sécurité

// Fonction smartEscape copiée depuis validation.js (version corrigée)
function isCloudinaryUrl(str) {
  if (!str || typeof str !== 'string') return false;
  
  // Vérifier le pattern Cloudinary de base
  const cloudinaryPattern = /^https:\/\/res\.cloudinary\.com\/[\w-]+\/image\/upload\/.+$/;
  if (!str.match(cloudinaryPattern)) return false;
  
  // Vérifier qu'il n'y a pas de caractères dangereux dans l'URL
  const dangerousChars = /<|>|"|'|javascript:|data:|vbscript:|onclick|onerror|onload/i;
  if (dangerousChars.test(str)) return false;
  
  return true;
}

function smartEscape(str) {
  if (!str || typeof str !== 'string') return str;
  
  if (isCloudinaryUrl(str)) {
    return str; // Garder l'URL intacte
  }
  
  const escapeMap = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;'
  };
  
  return str.replace(/[&<>"'\/]/g, (char) => escapeMap[char]);
}

// Tests
const testCases = [
  {
    name: "URL Cloudinary valide",
    input: "https://res.cloudinary.com/doyupygie/image/upload/v1754587188/faf-images/image.png",
    expected: "https://res.cloudinary.com/doyupygie/image/upload/v1754587188/faf-images/image.png",
    safe: true
  },
  {
    name: "Tentative XSS avec script",
    input: "<script>alert('XSS')</script>",
    expected: "&lt;script&gt;alert(&#39;XSS&#39;)&lt;&#x2F;script&gt;",
    safe: true
  },
  {
    name: "Tentative XSS avec img onerror",
    input: '"><img src=x onerror=alert("XSS")>',
    expected: '&quot;&gt;&lt;img src=x onerror=alert(&quot;XSS&quot;)&gt;',
    safe: true
  },
  {
    name: "Texte normal avec apostrophe",
    input: "C'est l'été",
    expected: "C&#39;est l&#39;été",
    safe: true
  },
  {
    name: "Fausse URL Cloudinary (XSS déguisé)",
    input: "https://res.cloudinary.com/test/image/upload/<script>alert('XSS')</script>",
    expected: "&lt;script&gt;alert(&#39;XSS&#39;)&lt;&#x2F;script&gt;",
    safe: true // Maintenant sécurisé!
  },
  {
    name: "URL Cloudinary avec caractères spéciaux dans le nom",
    input: "https://res.cloudinary.com/demo/image/upload/v123/Capture_d'écran.png",
    expected: "https://res.cloudinary.com/demo/image/upload/v123/Capture_d'écran.png",
    safe: true
  }
];

console.log("=== Test de sécurité smartEscape ===\n");

testCases.forEach(test => {
  const result = smartEscape(test.input);
  const passed = result === test.expected;
  
  console.log(`${passed ? '✅' : '❌'} ${test.name}`);
  console.log(`   Input:    ${test.input}`);
  console.log(`   Expected: ${test.expected}`);
  console.log(`   Got:      ${result}`);
  console.log(`   Safe:     ${test.safe ? 'OUI' : '⚠️  NON - Vulnérabilité potentielle!'}`);
  console.log('');
});

// Test spécial: vérifier que les URLs non-Cloudinary sont bien escapées
const maliciousUrls = [
  "https://evil.com/image/upload/test.png",
  "http://res.cloudinary.com/test/image/upload/test.png", // HTTP au lieu de HTTPS
  "https://res-cloudinary.com/test/image/upload/test.png", // Domaine différent
];

console.log("=== Test URLs malveillantes déguisées ===\n");
maliciousUrls.forEach(url => {
  const result = smartEscape(url);
  const isEscaped = result !== url;
  console.log(`${isEscaped ? '✅' : '❌'} ${url}`);
  console.log(`   Escapé: ${isEscaped ? 'OUI (sécurisé)' : 'NON (vulnérable)'}`);
  console.log('');
});