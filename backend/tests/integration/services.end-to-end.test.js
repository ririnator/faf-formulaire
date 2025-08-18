const mongoose = require('mongoose');
const { setupTestDatabase, teardownTestDatabase, cleanupDatabase } = require('./setup-integration');

const ServiceFactory = require('../../services/serviceFactory');
const User = require('../../models/User');
const Contact = require('../../models/Contact');
const Invitation = require('../../models/Invitation');
const Submission = require('../../models/Submission');
const Handshake = require('../../models/Handshake');

describe('Services End-to-End Integration Tests', () => {
  
  let serviceFactory;
  let contactService, invitationService, submissionService, handshakeService;
  let alice, bob, charlie, diana, eve;
  const currentMonth = new Date().toISOString().slice(0, 7);

  beforeAll(async () => {
    await setupTestDatabase();
    
    

    serviceFactory = ServiceFactory.create();
    contactService = serviceFactory.getContactService();
    invitationService = serviceFactory.getInvitationService();
    submissionService = serviceFactory.getSubmissionService();
    handshakeService = serviceFactory.getHandshakeService();
  });

  beforeEach(async () => {
    // Nettoyer toutes les collections
    await cleanupDatabase();

    // Créer des utilisateurs pour les tests
    const users = await User.insertMany([
      {
        username: 'alice_admin',
        email: 'alice@formafriend.com',
        password: 'secure123',
        role: 'admin',
        profile: {
          firstName: 'Alice',
          lastName: 'Manager'
        },
        metadata: {
          isActive: true,
          responseCount: 10,
          lastActive: new Date()
        }
      },
      {
        username: 'bob_user',
        email: 'bob@example.com',
        password: 'secure123',
        profile: {
          firstName: 'Bob',
          lastName: 'Smith'
        },
        metadata: {
          isActive: true,
          responseCount: 3,
          lastActive: new Date()
        }
      },
      {
        username: 'charlie_social',
        email: 'charlie@example.com',
        password: 'secure123',
        profile: {
          firstName: 'Charlie',
          lastName: 'Brown'
        },
        metadata: {
          isActive: true,
          responseCount: 7,
          lastActive: new Date()
        }
      },
      {
        username: 'diana_new',
        email: 'diana@example.com',
        password: 'secure123',
        profile: {
          firstName: 'Diana',
          lastName: 'Wilson'
        },
        metadata: {
          isActive: true,
          responseCount: 1,
          lastActive: new Date()
        }
      },
      {
        username: 'eve_external',
        email: 'eve@external.com',
        password: 'secure123',
        profile: {
          firstName: 'Eve',
          lastName: 'External'
        },
        metadata: {
          isActive: true,
          responseCount: 0,
          lastActive: new Date()
        }
      }
    ]);

    [alice, bob, charlie, diana, eve] = users;
  });

  afterAll(async () => {
    await teardownTestDatabase();
    
    
  });

  describe('Scénario Complet 1: Cycle de vie utilisateur complet', () => {
    it('devrait gérer le parcours complet d\'un utilisateur', async () => {
      // === PHASE 1: IMPORT DE CONTACTS ===
      console.log('Phase 1: Import de contacts par Alice (admin)');

      // 1.1. Alice (admin) importe ses contacts via CSV
      const csvData = `email,firstName,lastName,tags,notes
${bob.email},Bob,Smith,ami;travail,Collègue sympa
${charlie.email},Charlie,Brown,ami,Ami d'enfance  
diana@example.com,Diana,Wilson,potentiel,Rencontrée à un événement
newcomer@test.com,New,Comer,externe,Contact externe sans compte`;

      const importResult = await contactService.importCSV(csvData, alice._id, {
        skipDuplicates: true,
        createHandshakes: true
      });

      expect(importResult.total).toBe(4);
      expect(importResult.imported).toBe(4);
      expect(importResult.handshakesCreated).toBe(3); // Bob, Charlie, Diana existent
      expect(importResult.errors).toHaveLength(0);

      console.log(`✅ Contacts importés: ${importResult.imported}/${importResult.total}`);
      console.log(`✅ Handshakes créés automatiquement: ${importResult.handshakesCreated}`);

      // === PHASE 2: GESTION DES HANDSHAKES ===
      console.log('Phase 2: Gestion des handshakes');

      // 2.1. Vérifier que les handshakes ont été créés
      const aliceHandshakes = await handshakeService.getUserHandshakes(alice._id);
      expect(aliceHandshakes.handshakes.length).toBe(3);
      expect(aliceHandshakes.stats.totalSent).toBe(3);

      // 2.2. Bob accepte le handshake d'Alice
      const aliceBobHandshake = aliceHandshakes.handshakes.find(
        h => h.targetId.toString() === bob._id.toString()
      );
      
      await handshakeService.accept(
        aliceBobHandshake._id,
        bob._id,
        'Salut Alice ! Ravi de se connecter.'
      );

      // 2.3. Charlie accepte également
      const aliceCharlieHandshake = aliceHandshakes.handshakes.find(
        h => h.targetId.toString() === charlie._id.toString()
      );
      
      await handshakeService.accept(
        aliceCharlieHandshake._id,
        charlie._id,
        'Hey Alice ! Bien sûr, connectons-nous.'
      );

      // 2.4. Diana refuse poliment
      const aliceDianaHandshake = aliceHandshakes.handshakes.find(
        h => h.targetId.toString() === diana._id.toString()
      );
      
      await handshakeService.decline(
        aliceDianaHandshake._id,
        diana._id,
        'Merci Alice, mais je préfère attendre un peu.'
      );

      console.log('✅ Handshakes traités: Bob ✓, Charlie ✓, Diana ✗');

      // === PHASE 3: CRÉATION DES SOUMISSIONS ===
      console.log('Phase 3: Création des soumissions pour le matching');

      // 3.1. Alice crée sa soumission (profil complet)
      const aliceSubmission = await submissionService.createSubmission(
        alice._id,
        {
          responses: [
            { questionId: 'age', type: 'radio', answer: '30-35' },
            { questionId: 'location', type: 'radio', answer: 'Paris' },
            { questionId: 'profession', type: 'text', answer: 'Gestionnaire de communauté et organisatrice d\'événements' },
            { questionId: 'hobbies', type: 'text', answer: 'organisation d\'événements, lecture, cinéma, voyages culturels' },
            { questionId: 'personality', type: 'radio', answer: 'Extraverti' },
            { questionId: 'values', type: 'text', answer: 'authenticité, créativité, connexion humaine, découverte' },
            { questionId: 'goals', type: 'text', answer: 'créer des liens durables, organiser des rencontres, développer une communauté' }
          ],
          freeText: 'Je suis passionnée par la création de liens authentiques entre les personnes. J\'organise régulièrement des événements pour que les gens se rencontrent dans un cadre bienveillant.',
          month: currentMonth
        }
      );

      // 3.2. Bob crée sa soumission (profil compatible avec Alice)
      const bobSubmission = await submissionService.createSubmission(
        bob._id,
        {
          responses: [
            { questionId: 'age', type: 'radio', answer: '25-30' },
            { questionId: 'location', type: 'radio', answer: 'Paris' },
            { questionId: 'profession', type: 'text', answer: 'Développeur web freelance' },
            { questionId: 'hobbies', type: 'text', answer: 'technologie, cinéma, voyages, rencontres' },
            { questionId: 'personality', type: 'radio', answer: 'Ambivert' },
            { questionId: 'values', type: 'text', answer: 'innovation, connexion, apprentissage, authenticité' },
            { questionId: 'goals', type: 'text', answer: 'rencontrer des personnes inspirantes, collaborer sur des projets' }
          ],
          freeText: 'Je travaille dans la tech mais j\'aime aussi les interactions humaines. Je cherche à rencontrer des personnes créatives avec qui échanger des idées.',
          month: currentMonth
        }
      );

      // 3.3. Charlie crée sa soumission (moins compatible)
      const charlieSubmission = await submissionService.createSubmission(
        charlie._id,
        {
          responses: [
            { questionId: 'age', type: 'radio', answer: '35-40' },
            { questionId: 'location', type: 'radio', answer: 'Lyon' },
            { questionId: 'profession', type: 'text', answer: 'Professeur de mathématiques' },
            { questionId: 'hobbies', type: 'text', answer: 'mathématiques, échecs, lecture scientifique' },
            { questionId: 'personality', type: 'radio', answer: 'Introverti' },
            { questionId: 'values', type: 'text', answer: 'logique, précision, tranquillité, réflexion' },
            { questionId: 'goals', type: 'text', answer: 'approfondir mes connaissances, avoir des discussions intellectuelles' }
          ],
          freeText: 'Je suis quelqu\'un de plutôt calme qui aime les discussions profondes et intellectuelles. Je préfère les petits groupes aux grands événements.',
          month: currentMonth
        }
      );

      console.log('✅ Soumissions créées pour Alice, Bob et Charlie');

      // === PHASE 4: INVITATIONS ET LIENS ===
      console.log('Phase 4: Envoi d\'invitations via tokens');

      // 4.1. Alice envoie des invitations à des contacts externes
      const externalInvitation = await invitationService.createInvitation({
        fromUserId: alice._id,
        toEmail: 'newcomer@test.com',
        month: currentMonth,
        metadata: {
          campaign: 'friend_expansion',
          message: 'Salut ! J\'aimerais te faire découvrir Form-a-Friend.'
        }
      }, {
        ipAddress: '192.168.1.100',
        userAgent: 'Chrome/100.0',
        referrer: 'https://formafriend.com'
      });

      expect(externalInvitation.type).toBe('external');
      expect(externalInvitation.token).toBeDefined();

      // 4.2. Alice envoie aussi une invitation à Eve (utilisateur existant)
      const eveInvitation = await invitationService.createInvitation({
        fromUserId: alice._id,
        toEmail: eve.email,
        month: currentMonth,
        metadata: {
          campaign: 'friend_expansion'
        }
      });

      expect(eveInvitation.type).toBe('user');
      expect(eveInvitation.toUserId.toString()).toBe(eve._id.toString());

      // 4.3. Valider les invitations
      const externalValidation = await invitationService.validateInvitationToken(
        externalInvitation.token,
        { ipAddress: '192.168.1.100', userAgent: 'Chrome/100.0' }
      );

      const eveValidation = await invitationService.validateInvitationToken(
        eveInvitation.token
      );

      expect(externalValidation.valid).toBe(true);
      expect(eveValidation.valid).toBe(true);

      console.log('✅ Invitations envoyées et validées');

      // === PHASE 5: ANALYSE DE COMPATIBILITÉ ===
      console.log('Phase 5: Analyse de compatibilité et matching');

      // 5.1. Comparer Alice et Bob (devraient être très compatibles)
      const aliceBobComparison = await submissionService.compareSubmissions(
        alice._id,
        bob._id,
        currentMonth
      );

      expect(aliceBobComparison.compatibility.overallScore).toBeGreaterThan(70);
      expect(aliceBobComparison.compatibility.matches.length).toBeGreaterThan(2);

      // 5.2. Comparer Alice et Charlie (moins compatibles)
      const aliceCharlieComparison = await submissionService.compareSubmissions(
        alice._id,
        charlie._id,
        currentMonth
      );

      expect(aliceCharlieComparison.compatibility.overallScore)
        .toBeLessThan(aliceBobComparison.compatibility.overallScore);

      // 5.3. Trouver les meilleurs matches pour Alice
      const aliceMatches = await submissionService.findMatches(
        alice._id,
        currentMonth,
        { minCompatibility: 60 }
      );

      expect(aliceMatches.length).toBeGreaterThan(0);
      
      // Bob devrait être le premier match (le plus compatible)
      const bestMatch = aliceMatches[0];
      expect(bestMatch.user.username).toBe('bob_user');
      expect(bestMatch.compatibility.overallScore).toBeGreaterThan(70);

      console.log(`✅ Meilleur match pour Alice: ${bestMatch.user.username} (${bestMatch.compatibility.overallScore}% compatible)`);

      // === PHASE 6: TRACKING ET MÉTRIQUES ===
      console.log('Phase 6: Tracking et métriques');

      // 6.1. Mettre à jour le tracking des contacts
      const aliceContacts = await contactService.getContactsWithStats(alice._id);
      expect(aliceContacts.contacts.length).toBe(4);

      for (const contact of aliceContacts.contacts) {
        if (contact.status === 'active') {
          await contactService.updateTracking(contact._id, 'sent', {
            campaignType: 'monthly_form',
            timestamp: new Date()
          });
          
          if (contact.email === bob.email || contact.email === charlie.email) {
            await contactService.updateTracking(contact._id, 'opened');
            await contactService.updateTracking(contact._id, 'submitted', {
              formId: currentMonth,
              completionTime: Math.random() * 300 + 60 // 1-5 minutes
            });
          }
        }
      }

      // 6.2. Obtenir les statistiques finales
      const finalContactStats = await contactService.getContactStats(alice._id);
      const finalHandshakeStats = await handshakeService.getUserHandshakeStats(alice._id);
      const finalSubmissionStats = await submissionService.getSubmissionStats();
      const finalInvitationStats = await invitationService.getInvitationStats(alice._id);

      console.log('📊 Statistiques finales:');
      console.log(`   Contacts: ${finalContactStats.basic.total} (${finalContactStats.basic.withHandshake} avec handshake)`);
      console.log(`   Handshakes: ${finalHandshakeStats.totalHandshakes} (${finalHandshakeStats.totalAccepted} acceptés)`);
      console.log(`   Soumissions: ${finalSubmissionStats.basic.totalSubmissions} (${finalSubmissionStats.basic.uniqueUsersCount} utilisateurs uniques)`);
      console.log(`   Invitations: ${finalInvitationStats.basic.total} (taux de réponse: ${finalInvitationStats.responseRate}%)`);

      // === VÉRIFICATIONS FINALES ===
      expect(finalContactStats.basic.total).toBe(4);
      expect(finalContactStats.basic.withHandshake).toBe(3);
      expect(finalHandshakeStats.totalAccepted).toBe(2);
      expect(finalSubmissionStats.basic.totalSubmissions).toBe(3);
      expect(finalInvitationStats.basic.total).toBe(2);

      console.log('✅ Scénario complet réussi !');
    });
  });

  describe('Scénario Complet 2: Workflow événementiel avec invitations multiples', () => {
    it('devrait gérer un événement Form-a-Friend avec invitations en masse', async () => {
      // === PHASE 1: PRÉPARATION DE L\'ÉVÉNEMENT ===
      console.log('Phase 1: Alice prépare un événement Form-a-Friend');

      // 1.1. Alice import une grande liste de contacts
      const eventContacts = [];
      for (let i = 1; i <= 10; i++) {
        eventContacts.push(`participant${i}@event.com,Participant,${i},événement,Participant à l'événement Form-a-Friend`);
      }
      
      const csvEventData = `email,firstName,lastName,tags,notes\n${eventContacts.join('\n')}`;
      
      const eventImport = await contactService.importCSV(csvEventData, alice._id, {
        batchSize: 5,
        defaultSource: 'event_registration'
      });

      expect(eventImport.total).toBe(10);
      expect(eventImport.imported).toBe(10);

      // 1.2. Ajouter les utilisateurs existants aux contacts
      await contactService.addContact({
        email: bob.email,
        firstName: 'Bob',
        lastName: 'Smith',
        tags: ['événement', 'ami'],
        notes: 'Participant confirmé'
      }, alice._id);

      await contactService.addContact({
        email: charlie.email,
        firstName: 'Charlie',
        lastName: 'Brown',
        tags: ['événement', 'ami'],
        notes: 'Participant confirmé'
      }, alice._id);

      console.log('✅ Liste des participants créée (12 contacts)');

      // === PHASE 2: ENVOI D\'INVITATIONS EN MASSE ===
      console.log('Phase 2: Envoi d\'invitations pour l\'événement');

      // 2.1. Envoyer des invitations à tous les contacts avec tag "événement"
      const eventContacts2 = await contactService.searchContacts(
        alice._id,
        'événement'
      );

      const invitationPromises = eventContacts2.map(contact => 
        invitationService.createInvitation({
          fromUserId: alice._id,
          toEmail: contact.email,
          month: currentMonth,
          metadata: {
            eventName: 'Form-a-Friend Meetup Paris',
            eventDate: '2024-03-15',
            campaign: 'event_march_2024'
          }
        }, {
          ipAddress: '10.0.1.50',
          userAgent: 'EventManager/2.0'
        })
      );

      const invitations = await Promise.all(invitationPromises);
      
      console.log(`✅ ${invitations.length} invitations envoyées`);

      // 2.2. Simuler l'ouverture de quelques invitations
      const openedInvitations = invitations.slice(0, 6);
      for (const invitation of openedInvitations) {
        await invitationService.validateInvitationToken(
          invitation.token,
          { ipAddress: '10.0.1.50' }
        );
      }

      // === PHASE 3: CRÉATION DES PROFILS PARTICIPANTS ===
      console.log('Phase 3: Les participants créent leurs profils');

      // 3.1. Bob crée un profil détaillé
      const bobEventProfile = await submissionService.createSubmission(
        bob._id,
        {
          responses: [
            { questionId: 'event_role', type: 'radio', answer: 'Participant actif' },
            { questionId: 'interests', type: 'text', answer: 'technologie, entrepreneuriat, networking' },
            { questionId: 'experience', type: 'radio', answer: '3-5 ans' },
            { questionId: 'goals', type: 'text', answer: 'rencontrer des cofondateurs potentiels, échanger sur les dernières tendances tech' },
            { questionId: 'availability', type: 'radio', answer: 'Très disponible' },
            { questionId: 'preferred_format', type: 'radio', answer: 'Discussions en petit groupe' }
          ],
          freeText: 'Je suis développeur freelance et j\'aimerais rencontrer d\'autres entrepreneurs tech pour échanger des idées et peut-être collaborer.',
          month: currentMonth,
          invitationToken: invitations.find(inv => inv.toEmail === bob.email)?.token
        }
      );

      // 3.2. Charlie crée un profil différent
      const charlieEventProfile = await submissionService.createSubmission(
        charlie._id,
        {
          responses: [
            { questionId: 'event_role', type: 'radio', answer: 'Observateur curieux' },
            { questionId: 'interests', type: 'text', answer: 'éducation, pédagogie, psychologie' },
            { questionId: 'experience', type: 'radio', answer: '5+ ans' },
            { questionId: 'goals', type: 'text', answer: 'comprendre comment créer des liens sociaux, apprendre de nouvelles approches' },
            { questionId: 'availability', type: 'radio', answer: 'Moyennement disponible' },
            { questionId: 'preferred_format', type: 'radio', answer: 'Conférences et présentations' }
          ],
          freeText: 'En tant qu\'enseignant, je m\'intéresse aux dynamiques sociales et aux méthodes pour aider les gens à se connecter.',
          month: currentMonth,
          invitationToken: invitations.find(inv => inv.toEmail === charlie.email)?.token
        }
      );

      console.log('✅ Profils participants créés');

      // === PHASE 4: MATCHING ET RECOMMANDATIONS ===
      console.log('Phase 4: Génération des matchings pour l\'événement');

      // 4.1. Analyser la compatibilité entre participants
      const participantComparison = await submissionService.compareSubmissions(
        bob._id,
        charlie._id,
        currentMonth
      );

      // 4.2. Trouver les meilleurs matches pour chaque participant actif
      const bobMatches = await submissionService.findMatches(
        bob._id,
        currentMonth,
        { minCompatibility: 40 } // Plus permissif pour un événement
      );

      const charlieMatches = await submissionService.findMatches(
        charlie._id,
        currentMonth,
        { minCompatibility: 40 }
      );

      console.log(`✅ Matches trouvés - Bob: ${bobMatches.length}, Charlie: ${charlieMatches.length}`);

      // === PHASE 5: GESTION POST-ÉVÉNEMENT ===
      console.log('Phase 5: Suivi post-événement');

      // 5.1. Créer des handshakes entre participants qui se sont bien entendus
      const postEventHandshake = await handshakeService.createMutual(
        bob._id,
        charlie._id,
        {
          message: 'Super de t\'avoir rencontré à l\'événement Form-a-Friend ! Restons en contact.',
          source: 'event_meetup',
          metadata: {
            eventName: 'Form-a-Friend Meetup Paris',
            meetingContext: 'discussion_tech_education'
          }
        }
      );

      expect(postEventHandshake.created).toBe(true);

      // 5.2. Charlie accepte la connexion
      const acceptedConnection = await handshakeService.accept(
        postEventHandshake.handshake._id,
        charlie._id,
        'Oui, avec plaisir ! J\'ai beaucoup apprécié notre discussion sur l\'intersection tech/éducation.'
      );

      expect(acceptedConnection.success).toBe(true);

      // 5.3. Mettre à jour le tracking pour mesurer le succès de l'événement
      const eventContactsTracked = await contactService.getContactsWithStats(
        alice._id,
        { tags: ['événement'] }
      );

      for (const contact of eventContactsTracked.contacts.slice(0, 8)) {
        await contactService.updateTracking(contact._id, 'sent');
        await contactService.updateTracking(contact._id, 'opened');
        
        if (Math.random() > 0.3) { // 70% de taux de participation
          await contactService.updateTracking(contact._id, 'submitted', {
            eventAttended: true,
            satisfactionScore: Math.floor(Math.random() * 3) + 3 // 3-5
          });
        }
      }

      // === PHASE 6: ANALYSES FINALES ===
      console.log('Phase 6: Analyses post-événement');

      // 6.1. Statistiques des invitations
      const invitationStats = await invitationService.getInvitationStats(alice._id);
      console.log(`📊 Taux de réponse aux invitations: ${invitationStats.responseRate}%`);

      // 6.2. Statistiques des soumissions
      const submissionStats = await submissionService.getSubmissionStats({
        month: currentMonth
      });
      console.log(`📊 Participants actifs: ${submissionStats.basic.totalSubmissions}/${invitationStats.basic.total}`);

      // 6.3. Nouveaux handshakes créés
      const newConnections = await handshakeService.getUserHandshakeStats(bob._id);
      console.log(`📊 Nouvelles connexions: ${newConnections.totalAccepted}`);

      // 6.4. Analyser l'impact sur le réseau d'Alice
      const aliceNetwork = await contactService.getContactStats(alice._id);
      const aliceConnections = await handshakeService.getUserHandshakeStats(alice._id);

      console.log('📊 Impact sur le réseau d\'Alice:');
      console.log(`   Contacts totaux: ${aliceNetwork.basic.total}`);
      console.log(`   Taux de réponse moyen: ${Math.round(aliceNetwork.basic.avgResponseRate || 0)}%`);
      console.log(`   Connexions actives: ${aliceConnections.totalAccepted}`);

      // === VÉRIFICATIONS FINALES ===
      expect(invitationStats.basic.total).toBeGreaterThanOrEqual(10);
      expect(submissionStats.basic.totalSubmissions).toBeGreaterThanOrEqual(2);
      expect(newConnections.totalAccepted).toBe(1);
      expect(aliceNetwork.basic.total).toBeGreaterThanOrEqual(12);

      console.log('✅ Événement Form-a-Friend géré avec succès !');
    });
  });

  describe('Scénario Complet 3: Système de recommandations intelligent', () => {
    it('devrait générer des recommandations intelligentes basées sur l\'historique', async () => {
      // === PHASE 1: CONSTRUCTION DE L\'HISTORIQUE ===
      console.log('Phase 1: Construction de l\'historique des interactions');

      // 1.1. Créer un réseau initial de connections
      const connections = [
        [alice, bob, 'Collègues devenus amis'],
        [alice, charlie, 'Rencontre événement'],
        [bob, diana, 'Projet collaboratif'],
        [charlie, eve, 'Formation commune']
      ];

      const establishedHandshakes = [];
      for (const [user1, user2, context] of connections) {
        const handshake = await handshakeService.createMutual(user1._id, user2._id, {
          message: `Connexion: ${context}`,
          source: 'history_building'
        });
        
        await handshakeService.accept(handshake.handshake._id, user2._id);
        establishedHandshakes.push(handshake.handshake);
      }

      console.log('✅ Réseau initial établi (4 connexions)');

      // 1.2. Créer des soumissions avec des patterns de compatibilité
      const profileTypes = {
        alice: {
          interests: 'organisation, leadership, créativité',
          values: 'connexion, innovation, communauté',
          personality: 'Extraverti',
          lifestyle: 'urbain_actif'
        },
        bob: {
          interests: 'technologie, innovation, entrepreneuriat',
          values: 'efficacité, création, collaboration',
          personality: 'Ambivert',
          lifestyle: 'urbain_tech'
        },
        charlie: {
          interests: 'éducation, psychologie, développement personnel',
          values: 'croissance, compréhension, patience',
          personality: 'Introverti',
          lifestyle: 'équilibré_réfléchi'
        },
        diana: {
          interests: 'art, design, expression créative',
          values: 'beauté, authenticité, inspiration',
          personality: 'Extraverti',
          lifestyle: 'créatif_bohème'
        },
        eve: {
          interests: 'voyage, cultures, langues',
          values: 'découverte, ouverture, aventure',
          personality: 'Extraverti',
          lifestyle: 'nomade_culturel'
        }
      };

      for (const [userKey, user] of Object.entries({ alice, bob, charlie, diana, eve })) {
        const profile = profileTypes[userKey];
        await submissionService.createSubmission(user._id, {
          responses: [
            { questionId: 'interests', type: 'text', answer: profile.interests },
            { questionId: 'values', type: 'text', answer: profile.values },
            { questionId: 'personality', type: 'radio', answer: profile.personality },
            { questionId: 'lifestyle', type: 'radio', answer: profile.lifestyle },
            { questionId: 'openness', type: 'radio', answer: 'Très ouvert' },
            { questionId: 'goals', type: 'text', answer: `Développer mon réseau dans ${profile.interests.split(',')[0]}` }
          ],
          freeText: `Je suis passionné par ${profile.interests} et je cherche à rencontrer des personnes qui partagent ces intérêts.`,
          month: currentMonth
        });
      }

      console.log('✅ Profils détaillés créés pour analyse');

      // === PHASE 2: ANALYSE DES PATTERNS DE COMPATIBILITÉ ===
      console.log('Phase 2: Analyse des patterns de compatibilité');

      // 2.1. Analyser toutes les combinaisons possibles
      const users = [alice, bob, charlie, diana, eve];
      const compatibilityMatrix = {};

      for (let i = 0; i < users.length; i++) {
        for (let j = i + 1; j < users.length; j++) {
          const user1 = users[i];
          const user2 = users[j];
          
          const comparison = await submissionService.compareSubmissions(
            user1._id,
            user2._id,
            currentMonth
          );
          
          const key = `${user1.username}_${user2.username}`;
          compatibilityMatrix[key] = {
            score: comparison.compatibility.overallScore,
            matches: comparison.compatibility.matches.length,
            differences: comparison.compatibility.differences.length,
            recommendations: comparison.compatibility.recommendations
          };
        }
      }

      console.log('📊 Matrice de compatibilité calculée');
      Object.entries(compatibilityMatrix).forEach(([pair, data]) => {
        console.log(`   ${pair}: ${data.score}% (${data.matches} matches, ${data.differences} différences)`);
      });

      // === PHASE 3: GÉNÉRATION DE RECOMMANDATIONS INTELLIGENTES ===
      console.log('Phase 3: Génération de recommandations');

      // 3.1. Recommandations pour Alice basées sur ses connexions existantes
      const aliceMatches = await submissionService.findMatches(
        alice._id,
        currentMonth,
        { minCompatibility: 50, limit: 10 }
      );

      // 3.2. Recommandations de handshakes pour Alice
      const aliceSuggestions = await handshakeService.getSuggestions(
        alice._id,
        { limit: 5, excludeExisting: true }
      );

      console.log(`✅ Recommandations pour Alice: ${aliceMatches.length} matches, ${aliceSuggestions.length} suggestions`);

      // 3.3. Analyser les patterns dans les recommandations
      const highCompatibilityUsers = aliceMatches.filter(m => m.compatibility.overallScore >= 75);
      const mediumCompatibilityUsers = aliceMatches.filter(m => 
        m.compatibility.overallScore >= 50 && m.compatibility.overallScore < 75
      );

      console.log(`📊 Recommandations par niveau - Élevé: ${highCompatibilityUsers.length}, Moyen: ${mediumCompatibilityUsers.length}`);

      // === PHASE 4: SIMULATION D\'ACTIONS BASÉES SUR LES RECOMMANDATIONS ===
      console.log('Phase 4: Actions basées sur les recommandations');

      // 4.1. Alice suit les recommandations et crée de nouveaux handshakes
      const topRecommendations = aliceMatches.slice(0, 2);
      const newHandshakes = [];

      for (const recommendation of topRecommendations) {
        if (recommendation.compatibility.overallScore >= 70) {
          const reasonsText = recommendation.compatibility.recommendations
            .slice(0, 2)
            .map(r => r.message)
            .join(' ');

          const newHandshake = await handshakeService.createMutual(
            alice._id,
            recommendation.user._id,
            {
              message: `Salut ! D'après nos profils, nous avons beaucoup en commun. ${reasonsText} J'aimerais faire ta connaissance !`,
              source: 'ai_recommendation',
              metadata: {
                compatibilityScore: recommendation.compatibility.overallScore,
                recommendationReasons: recommendation.compatibility.recommendations.slice(0, 3),
                algorithm: 'form_a_friend_v2'
              }
            }
          );

          newHandshakes.push({
            handshake: newHandshake.handshake,
            targetUser: recommendation.user,
            score: recommendation.compatibility.overallScore
          });
        }
      }

      console.log(`✅ ${newHandshakes.length} nouveaux handshakes créés basés sur les recommandations`);

      // 4.2. Réponses aux nouveaux handshakes
      for (const { handshake, targetUser, score } of newHandshakes) {
        // Probabilité d'acceptation basée sur le score de compatibilité
        const acceptanceProbability = (score - 50) / 50; // 50% = 0%, 100% = 100%
        
        if (Math.random() < acceptanceProbability) {
          await handshakeService.accept(
            handshake._id,
            targetUser._id,
            'Salut Alice ! Effectivement, nos profils semblent bien alignés. Ravi de faire ta connaissance !'
          );
          console.log(`✅ ${targetUser.username} a accepté (score: ${score}%)`);
        } else {
          await handshakeService.decline(
            handshake._id,
            targetUser._id,
            'Merci Alice, mais je ne peux pas accepter de nouvelles connexions pour le moment.'
          );
          console.log(`❌ ${targetUser.username} a décliné (score: ${score}%)`);
        }
      }

      // === PHASE 5: MESURE DE L\'EFFICACITÉ DU SYSTÈME ===
      console.log('Phase 5: Mesure de l\'efficacité');

      // 5.1. Analyser les taux de réussite
      const finalAliceStats = await handshakeService.getUserHandshakeStats(alice._id);
      const aiRecommendationSuccess = newHandshakes.filter(async ({ handshake }) => {
        const updated = await Handshake.findById(handshake._id);
        return updated.status === 'accepted';
      }).length;

      console.log(`📊 Efficacité des recommandations IA:`);
      console.log(`   Handshakes totaux d'Alice: ${finalAliceStats.totalHandshakes}`);
      console.log(`   Taux d'acceptation global: ${finalAliceStats.acceptanceRate}%`);
      console.log(`   Recommandations IA créées: ${newHandshakes.length}`);

      // 5.2. Calculer l'amélioration du réseau
      const aliceNetworkGrowth = await contactService.getContactStats(alice._id);
      const networkEfficiency = (aliceNetworkGrowth.basic.totalResponsesReceived / 
                                 aliceNetworkGrowth.basic.totalInvitationsSent) * 100;

      console.log(`📊 Croissance du réseau:`);
      console.log(`   Contacts actifs: ${aliceNetworkGrowth.basic.withHandshake}`);
      console.log(`   Efficacité réseau: ${Math.round(networkEfficiency)}%`);

      // === PHASE 6: GÉNÉRATION DE NOUVELLES RECOMMANDATIONS AFFINÉES ===
      console.log('Phase 6: Recommandations affinées post-apprentissage');

      // 6.1. Utiliser l'historique des succès pour affiner les recommandations
      const successfulConnections = await Handshake.find({
        requesterId: alice._id,
        status: 'accepted'
      }).populate('targetId');

      // 6.2. Analyser les patterns des connexions réussies
      const successPatterns = {};
      for (const connection of successfulConnections) {
        const targetSubmission = await submissionService.getSubmissionByUser(
          connection.targetId._id,
          currentMonth
        );
        
        if (targetSubmission) {
          // Analyser les caractéristiques communes
          const personality = targetSubmission.responses.find(r => r.questionId === 'personality')?.answer;
          const lifestyle = targetSubmission.responses.find(r => r.questionId === 'lifestyle')?.answer;
          
          successPatterns[personality] = (successPatterns[personality] || 0) + 1;
          successPatterns[lifestyle] = (successPatterns[lifestyle] || 0) + 1;
        }
      }

      console.log('📊 Patterns des connexions réussies:', successPatterns);

      // === VÉRIFICATIONS FINALES ===
      expect(Object.keys(compatibilityMatrix).length).toBe(10); // 5C2 = 10 combinations
      expect(aliceMatches.length).toBeGreaterThan(0);
      expect(aliceSuggestions.length).toBeGreaterThan(0);
      expect(newHandshakes.length).toBeGreaterThan(0);
      expect(finalAliceStats.totalHandshakes).toBeGreaterThan(4); // Initial + nouveaux

      console.log('✅ Système de recommandations intelligent validé !');
    });
  });

  describe('Intégration ServiceFactory', () => {
    it('devrait fonctionner correctement via le ServiceFactory', async () => {
      // Vérifier que tous les services sont accessibles via le factory
      expect(serviceFactory.getContactService()).toBe(contactService);
      expect(serviceFactory.getInvitationService()).toBe(invitationService);
      expect(serviceFactory.getSubmissionService()).toBe(submissionService);
      expect(serviceFactory.getHandshakeService()).toBe(handshakeService);

      // Test rapide d'intégration
      const contact = await contactService.addContact({
        email: 'factory@test.com',
        firstName: 'Factory'
      }, alice._id);

      const invitation = await invitationService.createInvitation({
        fromUserId: alice._id,
        toEmail: 'factory@test.com',
        month: currentMonth
      });

      expect(contact.contact).toBeDefined();
      expect(invitation.token).toBeDefined();

      console.log('✅ ServiceFactory fonctionne correctement');
    });
  });
});