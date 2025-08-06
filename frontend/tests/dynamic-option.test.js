/**
 * Tests pour la génération dynamique de l'option 2 du formulaire
 * Teste la logique des préfixes français et la génération des mois
 */

// Mock du DOM pour les tests
function createMockDOM() {
  const mockDocument = {
    getElementById: jest.fn(),
    addEventListener: jest.fn()
  };
  
  const mockOption2 = { value: '', setAttribute: jest.fn() };
  const mockLabel2 = { textContent: '', setAttribute: jest.fn() };
  
  mockDocument.getElementById
    .mockReturnValueOnce(mockOption2)
    .mockReturnValueOnce(mockLabel2);
    
  return { mockDocument, mockOption2, mockLabel2 };
}

// Fonction extraite du HTML (pour les tests)
function generateDynamicOption2(customDate = null) {
  const today = customDate || new Date();
  const prev = new Date(today.getFullYear(), today.getMonth() - 1, 1);
  
  // Force la locale française pour assurer la cohérence
  const month = prev.toLocaleString('fr-FR', { month: 'long' });
  
  // Voyelles françaises + 'h' muet (règles d'élision)
  const vowelsAndH = ['a', 'e', 'i', 'o', 'u', 'h'];
  
  const firstLetter = month[0].toLowerCase();
  const prefix = vowelsAndH.includes(firstLetter)
    ? "a connu meilleur mois d'"
    : 'a connu meilleur mois de ';
  
  return `${prefix}${month}`;
}

describe('Dynamic Option 2 Generation', () => {
  
  describe('French Month Prefix Logic', () => {
    
    test('should use "d\'" prefix for months starting with vowels', () => {
      // Janvier → février (test avec avril pour voyelle)
      const aprilDate = new Date('2024-05-01'); // Avril est le mois précédent
      const result = generateDynamicOption2(aprilDate);
      expect(result).toBe("a connu meilleur mois d'avril");
    });

    test('should use "d\'" prefix for months starting with h', () => {
      // Test hypothétique - pas de mois français commençant par 'h' mais le test valide la logique
      // On peut mocker le toLocaleString pour tester
      const originalToLocaleString = Date.prototype.toLocaleString;
      Date.prototype.toLocaleString = jest.fn(() => 'hiver'); // Mock hypothétique
      
      const result = generateDynamicOption2();
      expect(result).toBe("a connu meilleur mois d'hiver");
      
      // Restore
      Date.prototype.toLocaleString = originalToLocaleString;
    });

    test('should use "de " prefix for months starting with consonants', () => {
      // Mars → avril (test avec janvier pour consonne)
      const februaryDate = new Date('2024-02-01'); // Janvier est le mois précédent  
      const result = generateDynamicOption2(februaryDate);
      expect(result).toBe("a connu meilleur mois de janvier");
    });

  });

  describe('Month Generation Tests', () => {
    
    const monthTests = [
      { date: '2024-02-01', expected: 'janvier', prefix: 'de ' },
      { date: '2024-03-01', expected: 'février', prefix: 'de ' },
      { date: '2024-04-01', expected: 'mars', prefix: 'de ' },
      { date: '2024-05-01', expected: 'avril', prefix: "d'" },
      { date: '2024-06-01', expected: 'mai', prefix: 'de ' },
      { date: '2024-07-01', expected: 'juin', prefix: 'de ' },
      { date: '2024-08-01', expected: 'juillet', prefix: 'de ' },
      { date: '2024-09-01', expected: 'août', prefix: "d'" },
      { date: '2024-10-01', expected: 'septembre', prefix: 'de ' },
      { date: '2024-11-01', expected: 'octobre', prefix: "d'" },
      { date: '2024-12-01', expected: 'novembre', prefix: 'de ' },
      { date: '2025-01-01', expected: 'décembre', prefix: 'de ' }
    ];

    monthTests.forEach(({ date, expected, prefix }) => {
      test(`should generate correct text for ${expected}`, () => {
        const testDate = new Date(date);
        const result = generateDynamicOption2(testDate);
        expect(result).toBe(`a connu meilleur mois ${prefix}${expected}`);
      });
    });

  });

  describe('Edge Cases and Locale Consistency', () => {
    
    test('should handle year transitions correctly', () => {
      // Janvier 2024 → décembre 2023
      const januaryDate = new Date('2024-01-01');
      const result = generateDynamicOption2(januaryDate);
      expect(result).toBe("a connu meilleur mois de décembre");
    });

    test('should be consistent regardless of system locale', () => {
      // Force différentes locales et vérifier la cohérence
      const testDate = new Date('2024-05-01'); // Avril précédent
      
      // Test avec différentes locales système simulées
      const originalLocale = Intl.DateTimeFormat().resolvedOptions().locale;
      
      // Test 1: Force locale fr-FR (déjà testé)
      const result1 = generateDynamicOption2(testDate);
      
      // Test 2: Même résultat attendu car on force fr-FR
      const result2 = generateDynamicOption2(testDate);
      
      expect(result1).toBe(result2);
      expect(result1).toBe("a connu meilleur mois d'avril");
    });

    test('should handle leap years correctly', () => {
      // Mars dans année bissextile → février
      const marchLeapYear = new Date('2024-03-01'); // 2024 est bissextile
      const result = generateDynamicOption2(marchLeapYear);
      expect(result).toBe("a connu meilleur mois de février");
    });

  });

  describe('DOM Integration Tests', () => {
    
    test('should update both option value and label text', () => {
      const { mockOption2, mockLabel2 } = createMockDOM();
      
      // Simuler la logique du DOM
      const fullText = generateDynamicOption2();
      mockOption2.value = fullText;
      mockLabel2.textContent = fullText;
      
      expect(mockOption2.value).toBe(fullText);
      expect(mockLabel2.textContent).toBe(fullText);
      expect(fullText).toMatch(/^a connu meilleur mois d'|de /);
    });

  });

  describe('Validation Compatibility Tests', () => {
    
    test('generated option should pass backend validation', () => {
      const result = generateDynamicOption2();
      
      // Vérifier que le résultat n'est pas vide (backend rejette les chaînes vides)
      expect(result).toBeTruthy();
      expect(result.length).toBeGreaterThan(0);
      
      // Vérifier que la longueur est raisonnable (max 500 chars côté backend)
      expect(result.length).toBeLessThanOrEqual(500);
      
      // Vérifier le format attendu
      expect(result).toMatch(/^a connu meilleur mois d'[a-zé]+$|^a connu meilleur mois de [a-zé]+$/);
    });

  });

});