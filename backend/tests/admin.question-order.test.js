// Tests pour l'ordre correct des questions dans l'interface admin
const request = require('supertest');
const { normalizeQuestion } = require('../utils/questionNormalizer');

describe('📋 Admin Question Order Tests', () => {
  
  describe('Question order logic (unit tests)', () => {
    
    // Simule la logique de tri des questions
    // 🔧 FIXED: Questions exactement comme dans index.html (sans : à la fin pour Q3-Q10)
    const QUESTION_ORDER = [
      "En rapide, comment ça va ?", // Q1 - PIE CHART
      "Possibilité d'ajouter un peu plus de détails à la question précédente :", // Q2
      "Le pulse check mensuel... montre une photo de toi ce mois-ci", // Q3 - PAS DE : à la fin
      "Est-ce que tu veux partager un truc cool que t'as fait ce mois-ci ?", // Q4 - PAS DE : à la fin
      "C'est quoi la reaction pic que tu utilises le plus en ce moment ?", // Q5 - PAS DE : à la fin
      "Est-ce que t'as eu une conversation intéressante avec quelqu'un récemment ? De quoi est-ce que ça parlait ?", // Q6 - PAS DE : à la fin
      "Ta découverte culturelle du moment ? (film, série, resto, bar, zoo, belle femme, vêtement... une catégorie assez libre finalement)", // Q7 - PAS DE : à la fin
      "Est-ce que t'as une habitude ou une nouvelle routine que t'essaies d'implémenter ces temps-ci ? Si oui... est-ce que ça fonctionne... si non... est-ce que y'a un truc que tu voudrais implémenter ?", // Q8 - PAS DE : à la fin
      "Appel à un AMI : Est-ce que t'as un problème particulier pour lequel tu aurais besoin d'opinions tierces ? (exemple : poll pour ta prochaine teinture, recommandations de matelas, etc.)", // Q9 - PAS DE : à la fin
      "Pour terminer : une photo de toi qui touche de l'herbe ou un arbre" // Q10 - PAS DE : à la fin
    ];

    // Utilise la même fonction de normalisation que adminRoutes.js
    const normalizeForComparison = normalizeQuestion;

    const sortQuestionsByFormOrder = (questions) => {
      return questions.sort((a, b) => {
        const normalizedA = normalizeForComparison(a.question);
        const normalizedB = normalizeForComparison(b.question);
        
        let indexA = QUESTION_ORDER.findIndex(q => normalizeForComparison(q) === normalizedA);
        let indexB = QUESTION_ORDER.findIndex(q => normalizeForComparison(q) === normalizedB);
        
        if (indexA === -1) indexA = QUESTION_ORDER.length;
        if (indexB === -1) indexB = QUESTION_ORDER.length;
        
        return indexA - indexB;
      });
    };

    test('should sort questions in correct form order', () => {
      // Questions dans le désordre (comme MongoDB pourrait les retourner)
      const unorderedQuestions = [
        { question: "Pour terminer : une photo de toi qui touche de l'herbe ou un arbre", items: [] },
        { question: "En rapide, comment ça va ?", items: [] },
        { question: "C'est quoi la reaction pic que tu utilises le plus en ce moment ?", items: [] },
        { question: "Possibilité d'ajouter un peu plus de détails à la question précédente :", items: [] }
      ];

      const sorted = sortQuestionsByFormOrder([...unorderedQuestions]);

      // Vérifier que l'ordre correspond au formulaire
      expect(sorted[0].question).toBe("En rapide, comment ça va ?"); // Q1
      expect(sorted[1].question).toBe("Possibilité d'ajouter un peu plus de détails à la question précédente :"); // Q2
      expect(sorted[2].question).toBe("C'est quoi la reaction pic que tu utilises le plus en ce moment ?"); // Q5
      expect(sorted[3].question).toBe("Pour terminer : une photo de toi qui touche de l'herbe ou un arbre"); // Q10
    });

    test('should handle questions with extra whitespace', () => {
      const questionsWithWhitespace = [
        { question: "  Pour terminer : une photo de toi qui touche de l'herbe ou un arbre  ", items: [] },
        { question: "En rapide,  comment  ça va ?", items: [] }, // Espaces multiples
      ];

      const sorted = sortQuestionsByFormOrder(questionsWithWhitespace);

      expect(sorted[0].question).toContain("En rapide"); // Q1 first
      expect(sorted[1].question).toContain("Pour terminer"); // Q10 second
    });

    test('should put unknown questions at the end', () => {
      const mixedQuestions = [
        { question: "Question inconnue qui n'existe pas dans le formulaire", items: [] },
        { question: "En rapide, comment ça va ?", items: [] },
        { question: "Autre question inconnue", items: [] }
      ];

      const sorted = sortQuestionsByFormOrder(mixedQuestions);

      expect(sorted[0].question).toBe("En rapide, comment ça va ?"); // Q1 known
      expect(sorted[1].question).toBe("Question inconnue qui n'existe pas dans le formulaire"); // Unknown
      expect(sorted[2].question).toBe("Autre question inconnue"); // Unknown
    });

    test('should handle all 10 questions in correct order', () => {
      // Toutes les questions dans l'ordre inverse pour tester
      const allQuestionsReversed = QUESTION_ORDER
        .slice()
        .reverse()
        .map(question => ({ question, items: [] }));

      const sorted = sortQuestionsByFormOrder(allQuestionsReversed);

      // Vérifier que l'ordre est maintenant correct
      sorted.forEach((item, index) => {
        expect(normalizeForComparison(item.question))
          .toBe(normalizeForComparison(QUESTION_ORDER[index]));
      });
    });

    test('should handle empty or invalid questions', () => {
      const invalidQuestions = [
        { question: "", items: [] },
        { question: null, items: [] },
        { question: "   ", items: [] }, // Whitespace only
        { question: "En rapide, comment ça va ?", items: [] }
      ];

      const sorted = sortQuestionsByFormOrder(invalidQuestions);

      // Question valide devrait être première
      expect(sorted[0].question).toBe("En rapide, comment ça va ?");
      
      // Questions invalides à la fin
      expect(sorted.slice(1).every(item => 
        !item.question || !normalizeForComparison(item.question)
      )).toBe(true);
    });
  });

  describe('Question order matches form structure', () => {
    test('should have same question count as form', () => {
      // Le formulaire a exactement 10 questions
      const EXPECTED_QUESTION_COUNT = 10;
      
      const QUESTION_ORDER = [
        "En rapide, comment ça va ?", // Q1
        "Possibilité d'ajouter un peu plus de détails à la question précédente :", // Q2
        "Le pulse check mensuel... montre une photo de toi ce mois-ci :", // Q3
        "Est-ce que tu veux partager un truc cool que t'as fait ce mois-ci ? :", // Q4
        "C'est quoi la reaction pic que tu utilises le plus en ce moment ? :", // Q5
        "Est-ce que t'as eu une conversation intéressante avec quelqu'un récemment ? De quoi est-ce que ça parlait ? :", // Q6
        "Ta découverte culturelle du moment ? (film, série, resto, bar, zoo, belle femme, vêtement... une catégorie assez libre finalement) :", // Q7
        "Est-ce que t'as une habitude ou une nouvelle routine que t'essaies d'implémenter ces temps-ci ? Si oui... est-ce que ça fonctionne... si non... est-ce que y'a un truc que tu voudrais implémenter ? :", // Q8
        "Appel à un AMI : Est-ce que t'as un problème particulier pour lequel tu aurais besoin d'opinions tierces ? (exemple : poll pour ta prochaine teinture, recommandations de matelas, etc.) :", // Q9
        "Pour terminer : une photo de toi qui touche de l'herbe ou un arbre :" // Q10
      ];

      expect(QUESTION_ORDER).toHaveLength(EXPECTED_QUESTION_COUNT);
    });

    test('should have unique questions', () => {
      const QUESTION_ORDER = [
        "En rapide, comment ça va ?",
        "Possibilité d'ajouter un peu plus de détails à la question précédente :",
        "Le pulse check mensuel... montre une photo de toi ce mois-ci",
        "Est-ce que tu veux partager un truc cool que t'as fait ce mois-ci ?",
        "C'est quoi la reaction pic que tu utilises le plus en ce moment ?",
        "Est-ce que t'as eu une conversation intéressante avec quelqu'un récemment ? De quoi est-ce que ça parlait ?",
        "Ta découverte culturelle du moment ? (film, série, resto, bar, zoo, belle femme, vêtement... une catégorie assez libre finalement)",
        "Est-ce que t'as une habitude ou une nouvelle routine que t'essaies d'implémenter ces temps-ci ? Si oui... est-ce que ça fonctionne... si non... est-ce que y'a un truc que tu voudrais implémenter ?",
        "Appel à un AMI : Est-ce que t'as un problème particulier pour lequel tu aurais besoin d'opinions tierces ? (exemple : poll pour ta prochaine teinture, recommandations de matelas, etc.)",
        "Pour terminer : une photo de toi qui touche de l'herbe ou un arbre"
      ];

      const uniqueQuestions = new Set(QUESTION_ORDER);
      expect(uniqueQuestions.size).toBe(QUESTION_ORDER.length);
    });
  });
});