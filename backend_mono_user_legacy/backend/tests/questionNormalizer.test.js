/**
 * Tests pour le module questionNormalizer
 * Vérifie la normalisation des accents, ponctuation et variations de casse
 */

const { 
  normalizeQuestion, 
  normalizeForComparison, 
  areQuestionsEquivalent, 
  findQuestionIndex 
} = require('../utils/questionNormalizer');

describe('🔍 Question Normalizer Tests', () => {
  
  describe('Mixed accent variations', () => {
    test('should normalize French accents correctly', () => {
      const variations = [
        ['café', 'cafe'],
        ['réaction', 'reaction'],
        ['créé', 'cree'],
        ['élève', 'eleve'],
        ['être', 'etre'],
        ['naïf', 'naif'],
        ['coûter', 'couter'],
        ['hôtel', 'hotel'],
        ['français', 'francais'],
        ['Québec', 'quebec']
      ];

      variations.forEach(([accented, expected]) => {
        expect(normalizeQuestion(accented)).toBe(expected);
      });
    });

    test('should handle mixed accent/case combinations', () => {
      expect(normalizeQuestion('CAFÉ')).toBe('cafe');
      expect(normalizeQuestion('Réaction')).toBe('reaction'); 
      expect(normalizeQuestion('ÊTRE')).toBe('etre');
      expect(normalizeQuestion('nAïF')).toBe('naif');
    });

    test('should normalize complex French sentences', () => {
      const input = 'C\'est quoi la réaction pic que tu utilises le plus en ce moment ?';
      const expected = 'cest quoi la reaction pic que tu utilises le plus en ce moment';
      expect(normalizeQuestion(input)).toBe(expected);
    });
  });

  describe('Punctuation variations', () => {
    test('should remove common punctuation marks', () => {
      const variations = [
        ['question?', 'question'],
        ['question!', 'question'],
        ['question.', 'question'],
        ['question,', 'question'],
        ['question;', 'question'],
        ['question:', 'question'],
        ['question...', 'question'],
        ['question??', 'question'],
        ['question!!', 'question']
      ];

      variations.forEach(([punctuated, expected]) => {
        expect(normalizeQuestion(punctuated)).toBe(expected);
      });
    });

    test('should handle complex punctuation combinations', () => {
      expect(normalizeQuestion('question?!')).toBe('question');
      expect(normalizeQuestion('question...?')).toBe('question');
      expect(normalizeQuestion('question, vraiment?')).toBe('question vraiment');
      expect(normalizeQuestion('question: oui/non')).toBe('question ouinon');
    });

    test('should preserve spaces between words after punctuation removal', () => {
      expect(normalizeQuestion('mot1, mot2.')).toBe('mot1 mot2');
      expect(normalizeQuestion('mot1? mot2!')).toBe('mot1 mot2');
      expect(normalizeQuestion('mot1: mot2; mot3')).toBe('mot1 mot2 mot3');
    });
  });

  describe('Case variations', () => {
    test('should convert all cases to lowercase', () => {
      const variations = [
        ['QUESTION', 'question'],
        ['Question', 'question'], 
        ['qUeStIoN', 'question'],
        ['QuEsTiOn', 'question'],
        ['question', 'question']
      ];

      variations.forEach(([cased, expected]) => {
        expect(normalizeQuestion(cased)).toBe(expected);
      });
    });

    test('should handle mixed case sentences', () => {
      expect(normalizeQuestion('En RAPIDE, Comment ÇA va ?'))
        .toBe('en rapide comment ca va');
      expect(normalizeQuestion('EST-ce que TU veux'))
        .toBe('estce que tu veux');
    });
  });

  describe('Combined variations (real-world scenarios)', () => {
    test('should handle all variations together', () => {
      const baseQuestion = 'comment ca va';
      
      const variations = [
        'Comment ça va ?',
        'COMMENT ÇA VA?',
        'Comment ça va...',
        'comment, ça va !',
        'Comment... ça va???',
        '  Comment  ça   va  ?  ',
        'Comment\tça\nva ?'
      ];

      variations.forEach(variation => {
        expect(normalizeQuestion(variation)).toBe(baseQuestion);
      });
    });

    test('should match real form questions', () => {
      const formQuestion = "C'est quoi la reaction pic que tu utilises le plus en ce moment ?";
      const variations = [
        "C'est quoi la réaction pic que tu utilises le plus en ce moment?",
        "C'EST QUOI LA RÉACTION PIC QUE TU UTILISES LE PLUS EN CE MOMENT ?",
        "c'est quoi la reaction pic que tu utilises le plus en ce moment...",
        "  C'est quoi la réaction pic que tu utilises le plus en ce moment  ?  "
      ];

      const normalizedBase = normalizeQuestion(formQuestion);
      variations.forEach(variation => {
        expect(normalizeQuestion(variation)).toBe(normalizedBase);
      });
    });
  });

  describe('Utility functions', () => {
    test('areQuestionsEquivalent should work correctly', () => {
      expect(areQuestionsEquivalent('Café?', 'cafe')).toBe(true);
      expect(areQuestionsEquivalent('Question!', 'question')).toBe(true);
      expect(areQuestionsEquivalent('Different', 'autre')).toBe(false);
    });

    test('findQuestionIndex should find correct index', () => {
      const questions = ['Comment ça va ?', 'Quel âge ?', 'Où habites-tu ?'];
      
      expect(findQuestionIndex('comment ca va', questions)).toBe(0);
      expect(findQuestionIndex('QUEL ÂGE!', questions)).toBe(1);
      expect(findQuestionIndex('où habitestu', questions)).toBe(2);
      expect(findQuestionIndex('inexistant', questions)).toBe(-1);
    });

    test('normalizeForComparison should be backward compatible', () => {
      expect(normalizeForComparison('Test')).toBe(normalizeQuestion('Test'));
      expect(normalizeForComparison('Café?')).toBe(normalizeQuestion('Café?'));
    });
  });

  describe('Edge cases', () => {
    test('should handle empty and invalid inputs', () => {
      expect(normalizeQuestion('')).toBe('');
      expect(normalizeQuestion(null)).toBe('');
      expect(normalizeQuestion(undefined)).toBe('');
      expect(normalizeQuestion(123)).toBe('');
      expect(normalizeQuestion({})).toBe('');
    });

    test('should handle whitespace-only strings', () => {
      expect(normalizeQuestion('   ')).toBe('');
      expect(normalizeQuestion('\t\n\r')).toBe('');
      expect(normalizeQuestion('   \n   ')).toBe('');
    });

    test('should normalize multiple spaces', () => {
      expect(normalizeQuestion('mot1    mot2')).toBe('mot1 mot2');
      expect(normalizeQuestion('mot1\t\tmot2')).toBe('mot1 mot2');
      expect(normalizeQuestion('mot1\n\nmot2')).toBe('mot1 mot2');
    });

    test('should handle control characters', () => {
      expect(normalizeQuestion('mot1\u0000mot2')).toBe('mot1mot2');
      expect(normalizeQuestion('mot1\u001Fmot2')).toBe('mot1mot2');
      expect(normalizeQuestion('mot1\u007Fmot2')).toBe('mot1mot2');
    });
  });

  describe('Performance tests', () => {
    test('should handle long strings efficiently', () => {
      const longString = 'Très long texte avec accents éèàçù '.repeat(1000) + '?';
      const start = Date.now();
      const result = normalizeQuestion(longString);
      const end = Date.now();
      
      expect(end - start).toBeLessThan(100); // Should complete in <100ms
      expect(result.length).toBeGreaterThan(0);
      expect(result).not.toContain('é');
      expect(result).not.toContain('?');
    });

    test('should handle many normalization calls efficiently', () => {
      const questions = [
        'Comment ça va ?',
        'Quel âge as-tu ?',
        'Où habites-tu ?',
        'Que fais-tu ?'
      ];

      const start = Date.now();
      for (let i = 0; i < 1000; i++) {
        questions.forEach(q => normalizeQuestion(q));
      }
      const end = Date.now();

      expect(end - start).toBeLessThan(1000); // Should complete 4000 calls in <1s
    });
  });
});