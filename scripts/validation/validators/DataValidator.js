/**
 * Validateur de Données - Migration FAF
 * 
 * Vérifie l'intégrité des structures de données :
 * - Intégrité des structures de données
 * - Validation des types et formats
 * - Contrôle des valeurs null/undefined
 * - Vérification de l'encodage UTF-8
 * - Validation des contraintes de schéma
 * 
 * @author FAF Migration Team
 */

const BaseValidator = require('./BaseValidator');

class DataValidator extends BaseValidator {
    constructor(db, logger) {
        super('Validation des Données', db, logger);
        this.results = {
            schemaValidation: {},
            dataTypeValidation: {},
            nullValidation: {},
            encodingValidation: {},
            constraintValidation: {},
            dataQuality: {}
        };
        
        // Définition des schémas attendus
        this.schemas = this.defineSchemas();
    }

    /**
     * Validation principale des données
     */
    async validate() {
        this.logger.info('📋 Début de la validation des données...');
        
        try {
            await this.validateSchemas();
            await this.validateDataTypes();
            await this.validateNullValues();
            await this.validateEncoding();
            await this.validateConstraints();
            await this.assessDataQuality();
            
            const score = this.calculateScore();
            
            return {
                category: 'data',
                success: score >= 95,
                score,
                errors: this.errors,
                details: this.results,
                metadata: {
                    totalValidations: this.getTotalValidationCount(),
                    passedValidations: this.getPassedValidationCount()
                }
            };
            
        } catch (error) {
            this.addError('VALIDATION_FAILED', `Échec de la validation des données: ${error.message}`);
            throw error;
        }
    }

    /**
     * Définition des schémas de données attendus
     */
    defineSchemas() {
        return {
            users: {
                required: [
                    { name: '_id', type: 'objectId' },
                    { name: 'username', type: 'string' },
                    { name: 'email', type: 'string' },
                    { name: 'password', type: 'string' },
                    { name: 'role', type: 'string' }
                ],
                optional: [
                    { name: 'profile', type: 'object' },
                    { name: 'metadata', type: 'object' },
                    { name: 'migrationData', type: 'object' }
                ],
                constraints: {
                    'username': { minLength: 3, maxLength: 30, pattern: /^[a-zA-Z0-9_]+$/ },
                    'email': { pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ },
                    'role': { enum: ['user', 'admin'] },
                    'password': { minLength: 6 }
                }
            },
            
            submissions: {
                required: [
                    { name: '_id', type: 'objectId' },
                    { name: 'userId', type: 'objectId' },
                    { name: 'month', type: 'string' },
                    { name: 'responses', type: 'array' },
                    { name: 'submittedAt', type: 'date' }
                ],
                optional: [
                    { name: 'userRole', type: 'string' },
                    { name: 'legacyName', type: 'string' },
                    { name: 'migrationData', type: 'object' }
                ],
                constraints: {
                    'month': { pattern: /^\d{4}-\d{2}$/ },
                    'responses': { minLength: 1 },
                    'userRole': { enum: ['user', 'admin'] }
                }
            },
            
            invitations: {
                required: [
                    { name: '_id', type: 'objectId' },
                    { name: 'token', type: 'string' },
                    { name: 'userId', type: 'objectId' },
                    { name: 'status', type: 'string' },
                    { name: 'createdAt', type: 'date' }
                ],
                optional: [
                    { name: 'expiresAt', type: 'date' },
                    { name: 'migrationData', type: 'object' }
                ],
                constraints: {
                    'status': { enum: ['active', 'used', 'expired'] },
                    'token': { minLength: 1, maxLength: 255 }
                }
            },
            
            responses: {
                required: [
                    { name: '_id', type: 'objectId' },
                    { name: 'name', type: 'string' },
                    { name: 'month', type: 'string' },
                    { name: 'responses', type: 'array' },
                    { name: 'createdAt', type: 'date' }
                ],
                optional: [
                    { name: 'token', type: 'string' },
                    { name: 'isAdmin', type: 'boolean' }
                ],
                constraints: {
                    'name': { minLength: 2, maxLength: 100 },
                    'month': { pattern: /^\d{4}-\d{2}$/ },
                    'responses': { minLength: 1 }
                }
            }
        };
    }

    /**
     * Validation des schémas
     */
    async validateSchemas() {
        this.logger.info('📊 Validation des schémas de données...');
        
        const schemaResults = {};
        
        for (const [collectionName, schema] of Object.entries(this.schemas)) {
            this.logger.info(`  📋 Validation du schéma: ${collectionName}`);
            
            try {
                const result = await this.validateCollectionSchema(collectionName, schema);
                schemaResults[collectionName] = result;
                
            } catch (error) {
                this.addError(
                    'SCHEMA_VALIDATION_ERROR',
                    `Erreur de validation du schéma ${collectionName}: ${error.message}`,
                    { collection: collectionName }
                );
                schemaResults[collectionName] = { valid: false, errors: [error.message] };
            }
        }
        
        this.results.schemaValidation = schemaResults;
    }

    /**
     * Validation du schéma d'une collection
     */
    async validateCollectionSchema(collectionName, schema) {
        const documents = await this.db.collection(collectionName)
            .find({})
            .limit(100) // Limiter pour les performances
            .toArray();
        
        const validationResult = {
            totalDocuments: documents.length,
            validDocuments: 0,
            invalidDocuments: 0,
            errors: [],
            valid: true
        };
        
        for (const doc of documents) {
            const docErrors = [];
            
            // Validation des champs requis
            for (const requiredField of schema.required) {
                if (!this.validateRequiredField(doc, requiredField, docErrors)) {
                    validationResult.valid = false;
                }
            }
            
            // Validation des types de champs
            for (const field of [...schema.required, ...schema.optional]) {
                if (doc[field.name] !== undefined) {
                    if (!this.validateFieldType(doc[field.name], field.type)) {
                        docErrors.push(`Type invalide pour ${field.name}: attendu ${field.type}`);
                        validationResult.valid = false;
                    }
                }
            }
            
            if (docErrors.length === 0) {
                validationResult.validDocuments++;
            } else {
                validationResult.invalidDocuments++;
                validationResult.errors.push({
                    documentId: doc._id,
                    errors: docErrors
                });
                
                // Ajouter une erreur globale pour chaque document invalide
                this.addError(
                    'INVALID_DOCUMENT_SCHEMA',
                    `Document invalide dans ${collectionName}: ${doc._id}`,
                    { collection: collectionName, documentId: doc._id, errors: docErrors }
                );
            }
        }
        
        return validationResult;
    }

    /**
     * Validation d'un champ requis
     */
    validateRequiredField(document, field, errors) {
        if (!(field.name in document) || document[field.name] === null || document[field.name] === undefined) {
            errors.push(`Champ requis manquant: ${field.name}`);
            return false;
        }
        return true;
    }

    /**
     * Validation des types de données
     */
    async validateDataTypes() {
        this.logger.info('🔤 Validation des types de données...');
        
        const typeResults = {};
        
        for (const collectionName of Object.keys(this.schemas)) {
            this.logger.info(`  🔍 Types de données: ${collectionName}`);
            
            try {
                const result = await this.validateCollectionDataTypes(collectionName);
                typeResults[collectionName] = result;
                
            } catch (error) {
                this.addError(
                    'DATA_TYPE_VALIDATION_ERROR',
                    `Erreur de validation des types ${collectionName}: ${error.message}`,
                    { collection: collectionName }
                );
            }
        }
        
        this.results.dataTypeValidation = typeResults;
    }

    /**
     * Validation des types de données d'une collection
     */
    async validateCollectionDataTypes(collectionName) {
        const schema = this.schemas[collectionName];
        const pipeline = [
            { $limit: 1000 }, // Limiter pour les performances
            {
                $project: {
                    _id: 1,
                    typeValidation: {
                        $let: {
                            vars: {},
                            in: {}
                        }
                    }
                }
            }
        ];
        
        // Construction dynamique de la validation des types
        const typeChecks = {};
        for (const field of [...schema.required, ...schema.optional]) {
            typeChecks[field.name] = this.buildTypeCheck(field);
        }
        
        const documents = await this.db.collection(collectionName).find({}).limit(100).toArray();
        
        const result = {
            totalChecked: documents.length,
            typeErrors: [],
            validTypes: 0
        };
        
        for (const doc of documents) {
            let docValid = true;
            
            for (const field of [...schema.required, ...schema.optional]) {
                if (doc[field.name] !== undefined) {
                    if (!this.validateFieldType(doc[field.name], field.type)) {
                        result.typeErrors.push({
                            documentId: doc._id,
                            field: field.name,
                            expectedType: field.type,
                            actualType: typeof doc[field.name],
                            value: doc[field.name]
                        });
                        docValid = false;
                        
                        this.addError(
                            'INVALID_DATA_TYPE',
                            `Type invalide dans ${collectionName}.${field.name}: attendu ${field.type}, trouvé ${typeof doc[field.name]}`,
                            { 
                                collection: collectionName,
                                documentId: doc._id,
                                field: field.name,
                                expectedType: field.type,
                                actualType: typeof doc[field.name]
                            }
                        );
                    }
                }
            }
            
            if (docValid) {
                result.validTypes++;
            }
        }
        
        return result;
    }

    /**
     * Construction d'une vérification de type
     */
    buildTypeCheck(field) {
        switch (field.type) {
            case 'string':
                return { $type: 'string' };
            case 'number':
                return { $type: 'number' };
            case 'boolean':
                return { $type: 'bool' };
            case 'array':
                return { $type: 'array' };
            case 'object':
                return { $type: 'object' };
            case 'date':
                return { $type: 'date' };
            case 'objectId':
                return { $type: 'objectId' };
            default:
                return {};
        }
    }

    /**
     * Validation des valeurs null/undefined
     */
    async validateNullValues() {
        this.logger.info('❌ Validation des valeurs null/undefined...');
        
        const nullResults = {};
        
        for (const collectionName of Object.keys(this.schemas)) {
            this.logger.info(`  🔍 Valeurs null: ${collectionName}`);
            
            try {
                const result = await this.validateCollectionNullValues(collectionName);
                nullResults[collectionName] = result;
                
            } catch (error) {
                this.addError(
                    'NULL_VALIDATION_ERROR',
                    `Erreur de validation des valeurs null ${collectionName}: ${error.message}`,
                    { collection: collectionName }
                );
            }
        }
        
        this.results.nullValidation = nullResults;
    }

    /**
     * Validation des valeurs null d'une collection
     */
    async validateCollectionNullValues(collectionName) {
        const schema = this.schemas[collectionName];
        const requiredFields = schema.required.map(f => f.name);
        
        const result = {
            totalDocuments: 0,
            nullViolations: [],
            validDocuments: 0
        };
        
        // Recherche des documents avec des champs requis null
        for (const fieldName of requiredFields) {
            const nullDocuments = await this.db.collection(collectionName)
                .find({ 
                    $or: [
                        { [fieldName]: null },
                        { [fieldName]: { $exists: false } }
                    ]
                })
                .project({ _id: 1, [fieldName]: 1 })
                .toArray();
            
            for (const doc of nullDocuments) {
                result.nullViolations.push({
                    documentId: doc._id,
                    field: fieldName,
                    value: doc[fieldName]
                });
                
                this.addError(
                    'NULL_REQUIRED_FIELD',
                    `Champ requis null dans ${collectionName}.${fieldName}: ${doc._id}`,
                    { 
                        collection: collectionName,
                        documentId: doc._id,
                        field: fieldName
                    }
                );
            }
        }
        
        // Compter les documents valides
        const totalCount = await this.db.collection(collectionName).countDocuments({});
        result.totalDocuments = totalCount;
        result.validDocuments = totalCount - result.nullViolations.length;
        
        return result;
    }

    /**
     * Validation de l'encodage
     */
    async validateEncoding() {
        this.logger.info('🔤 Validation de l\'encodage UTF-8...');
        
        const encodingResults = {};
        
        for (const collectionName of Object.keys(this.schemas)) {
            this.logger.info(`  📝 Encodage: ${collectionName}`);
            
            try {
                const result = await this.validateCollectionEncoding(collectionName);
                encodingResults[collectionName] = result;
                
            } catch (error) {
                this.addError(
                    'ENCODING_VALIDATION_ERROR',
                    `Erreur de validation de l'encodage ${collectionName}: ${error.message}`,
                    { collection: collectionName }
                );
            }
        }
        
        this.results.encodingValidation = encodingResults;
    }

    /**
     * Validation de l'encodage d'une collection
     */
    async validateCollectionEncoding(collectionName) {
        const documents = await this.db.collection(collectionName)
            .find({})
            .limit(100)
            .toArray();
        
        const result = {
            totalDocuments: documents.length,
            encodingErrors: [],
            validEncoding: 0,
            frenchCharactersFound: 0
        };
        
        const frenchCharacters = /[àâäçéèêëîïôöùûüÿ]/i;
        
        for (const doc of documents) {
            let docValid = true;
            let hasFrenchChars = false;
            
            // Vérification récursive de l'encodage
            const checkEncoding = (obj, path = '') => {
                for (const [key, value] of Object.entries(obj)) {
                    const currentPath = path ? `${path}.${key}` : key;
                    
                    if (typeof value === 'string') {
                        // Vérification des caractères français
                        if (frenchCharacters.test(value)) {
                            hasFrenchChars = true;
                        }
                        
                        // Vérification des caractères de contrôle problématiques
                        if (this.hasEncodingIssues(value)) {
                            result.encodingErrors.push({
                                documentId: doc._id,
                                field: currentPath,
                                value: value,
                                issue: 'Caractères d\'encodage problématiques'
                            });
                            docValid = false;
                            
                            this.addError(
                                'ENCODING_ISSUE',
                                `Problème d'encodage dans ${collectionName}.${currentPath}: ${doc._id}`,
                                { 
                                    collection: collectionName,
                                    documentId: doc._id,
                                    field: currentPath,
                                    value: value
                                }
                            );
                        }
                    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
                        checkEncoding(value, currentPath);
                    } else if (Array.isArray(value)) {
                        value.forEach((item, index) => {
                            if (typeof item === 'object' && item !== null) {
                                checkEncoding(item, `${currentPath}[${index}]`);
                            } else if (typeof item === 'string') {
                                if (frenchCharacters.test(item)) {
                                    hasFrenchChars = true;
                                }
                                if (this.hasEncodingIssues(item)) {
                                    result.encodingErrors.push({
                                        documentId: doc._id,
                                        field: `${currentPath}[${index}]`,
                                        value: item,
                                        issue: 'Caractères d\'encodage problématiques'
                                    });
                                    docValid = false;
                                }
                            }
                        });
                    }
                }
            };
            
            checkEncoding(doc);
            
            if (docValid) {
                result.validEncoding++;
            }
            
            if (hasFrenchChars) {
                result.frenchCharactersFound++;
            }
        }
        
        return result;
    }

    /**
     * Détection des problèmes d'encodage
     */
    hasEncodingIssues(text) {
        // Caractères de contrôle problématiques
        const controlChars = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
        
        // Séquences d'encodage cassées communes
        const brokenEncoding = /â€™|â€œ|â€\x9d|Ã©|Ã\xa0/;
        
        return controlChars.test(text) || brokenEncoding.test(text);
    }

    /**
     * Validation des contraintes
     */
    async validateConstraints() {
        this.logger.info('⚖️ Validation des contraintes de données...');
        
        const constraintResults = {};
        
        for (const [collectionName, schema] of Object.entries(this.schemas)) {
            if (schema.constraints) {
                this.logger.info(`  🔒 Contraintes: ${collectionName}`);
                
                try {
                    const result = await this.validateCollectionConstraints(collectionName, schema.constraints);
                    constraintResults[collectionName] = result;
                    
                } catch (error) {
                    this.addError(
                        'CONSTRAINT_VALIDATION_ERROR',
                        `Erreur de validation des contraintes ${collectionName}: ${error.message}`,
                        { collection: collectionName }
                    );
                }
            }
        }
        
        this.results.constraintValidation = constraintResults;
    }

    /**
     * Validation des contraintes d'une collection
     */
    async validateCollectionConstraints(collectionName, constraints) {
        const documents = await this.db.collection(collectionName)
            .find({})
            .limit(1000)
            .toArray();
        
        const result = {
            totalDocuments: documents.length,
            constraintViolations: [],
            validDocuments: 0
        };
        
        for (const doc of documents) {
            let docValid = true;
            
            for (const [fieldName, constraint] of Object.entries(constraints)) {
                const value = doc[fieldName];
                
                if (value !== undefined && value !== null) {
                    const violations = this.checkFieldConstraints(value, constraint, fieldName);
                    
                    if (violations.length > 0) {
                        result.constraintViolations.push({
                            documentId: doc._id,
                            field: fieldName,
                            value: value,
                            violations: violations
                        });
                        docValid = false;
                        
                        for (const violation of violations) {
                            this.addError(
                                'CONSTRAINT_VIOLATION',
                                `Violation de contrainte dans ${collectionName}.${fieldName}: ${violation}`,
                                { 
                                    collection: collectionName,
                                    documentId: doc._id,
                                    field: fieldName,
                                    value: value,
                                    violation: violation
                                }
                            );
                        }
                    }
                }
            }
            
            if (docValid) {
                result.validDocuments++;
            }
        }
        
        return result;
    }

    /**
     * Vérification des contraintes d'un champ
     */
    checkFieldConstraints(value, constraints, fieldName) {
        const violations = [];
        
        // Contrainte de longueur minimale
        if (constraints.minLength !== undefined) {
            if (typeof value === 'string' && value.length < constraints.minLength) {
                violations.push(`Longueur minimale non respectée: ${value.length} < ${constraints.minLength}`);
            } else if (Array.isArray(value) && value.length < constraints.minLength) {
                violations.push(`Taille minimale du tableau non respectée: ${value.length} < ${constraints.minLength}`);
            }
        }
        
        // Contrainte de longueur maximale
        if (constraints.maxLength !== undefined) {
            if (typeof value === 'string' && value.length > constraints.maxLength) {
                violations.push(`Longueur maximale dépassée: ${value.length} > ${constraints.maxLength}`);
            } else if (Array.isArray(value) && value.length > constraints.maxLength) {
                violations.push(`Taille maximale du tableau dépassée: ${value.length} > ${constraints.maxLength}`);
            }
        }
        
        // Contrainte de pattern
        if (constraints.pattern && typeof value === 'string') {
            if (!constraints.pattern.test(value)) {
                violations.push(`Pattern non respecté: ${value} ne correspond pas à ${constraints.pattern}`);
            }
        }
        
        // Contrainte d'énumération
        if (constraints.enum && !constraints.enum.includes(value)) {
            violations.push(`Valeur non autorisée: ${value} (autorisées: ${constraints.enum.join(', ')})`);
        }
        
        return violations;
    }

    /**
     * Évaluation de la qualité des données
     */
    async assessDataQuality() {
        this.logger.info('⭐ Évaluation de la qualité des données...');
        
        const qualityResults = {
            completeness: {},
            consistency: {},
            accuracy: {},
            overall: {}
        };
        
        try {
            // Évaluation de la complétude
            await this.assessCompleteness(qualityResults.completeness);
            
            // Évaluation de la cohérence
            await this.assessConsistency(qualityResults.consistency);
            
            // Évaluation de la précision
            await this.assessAccuracy(qualityResults.accuracy);
            
            // Score global de qualité
            qualityResults.overall = this.calculateOverallQuality(qualityResults);
            
        } catch (error) {
            this.addError(
                'DATA_QUALITY_ASSESSMENT_ERROR',
                `Erreur d'évaluation de la qualité des données: ${error.message}`
            );
        }
        
        this.results.dataQuality = qualityResults;
    }

    /**
     * Évaluation de la complétude
     */
    async assessCompleteness(completenessResult) {
        for (const [collectionName, schema] of Object.entries(this.schemas)) {
            const totalDocs = await this.db.collection(collectionName).countDocuments({});
            const requiredFields = schema.required.map(f => f.name);
            
            const fieldCompleteness = {};
            
            for (const fieldName of requiredFields) {
                const completeCount = await this.db.collection(collectionName).countDocuments({
                    [fieldName]: { $exists: true, $ne: null }
                });
                
                fieldCompleteness[fieldName] = {
                    complete: completeCount,
                    total: totalDocs,
                    percentage: totalDocs > 0 ? (completeCount / totalDocs) * 100 : 100
                };
            }
            
            completenessResult[collectionName] = fieldCompleteness;
        }
    }

    /**
     * Évaluation de la cohérence
     */
    async assessConsistency(consistencyResult) {
        // Cohérence des formats de date
        const dateConsistency = await this.checkDateConsistency();
        
        // Cohérence des références
        const referenceConsistency = await this.checkReferenceConsistency();
        
        // Cohérence des énumérations
        const enumConsistency = await this.checkEnumConsistency();
        
        consistencyResult.dates = dateConsistency;
        consistencyResult.references = referenceConsistency;
        consistencyResult.enums = enumConsistency;
    }

    /**
     * Vérification de la cohérence des dates
     */
    async checkDateConsistency() {
        const dateFields = [
            { collection: 'users', field: 'metadata.registeredAt' },
            { collection: 'submissions', field: 'submittedAt' },
            { collection: 'invitations', field: 'createdAt' },
            { collection: 'responses', field: 'createdAt' }
        ];
        
        const consistency = {};
        
        for (const { collection, field } of dateFields) {
            try {
                const invalidDates = await this.db.collection(collection).aggregate([
                    { $match: { [field]: { $exists: true } } },
                    {
                        $addFields: {
                            isValidDate: {
                                $cond: {
                                    if: { $type: `$${field}` },
                                    then: { $eq: [{ $type: `$${field}` }, 'date'] },
                                    else: false
                                }
                            }
                        }
                    },
                    { $match: { isValidDate: false } },
                    { $count: 'invalidCount' }
                ]).toArray();
                
                consistency[`${collection}.${field}`] = {
                    invalidCount: invalidDates[0]?.invalidCount || 0,
                    isConsistent: (invalidDates[0]?.invalidCount || 0) === 0
                };
                
            } catch (error) {
                this.addError(
                    'DATE_CONSISTENCY_CHECK_ERROR',
                    `Erreur de vérification de cohérence des dates ${collection}.${field}: ${error.message}`
                );
            }
        }
        
        return consistency;
    }

    /**
     * Vérification de la cohérence des références
     */
    async checkReferenceConsistency() {
        const references = [
            { from: 'submissions', field: 'userId', to: 'users' },
            { from: 'invitations', field: 'userId', to: 'users' }
        ];
        
        const consistency = {};
        
        for (const ref of references) {
            try {
                const orphaned = await this.db.collection(ref.from).aggregate([
                    {
                        $lookup: {
                            from: ref.to,
                            localField: ref.field,
                            foreignField: '_id',
                            as: 'referenced'
                        }
                    },
                    {
                        $match: {
                            [ref.field]: { $ne: null },
                            referenced: { $size: 0 }
                        }
                    },
                    { $count: 'orphanedCount' }
                ]).toArray();
                
                consistency[`${ref.from}.${ref.field}`] = {
                    orphanedCount: orphaned[0]?.orphanedCount || 0,
                    isConsistent: (orphaned[0]?.orphanedCount || 0) === 0
                };
                
            } catch (error) {
                this.addError(
                    'REFERENCE_CONSISTENCY_CHECK_ERROR',
                    `Erreur de vérification de cohérence des références ${ref.from}.${ref.field}: ${error.message}`
                );
            }
        }
        
        return consistency;
    }

    /**
     * Vérification de la cohérence des énumérations
     */
    async checkEnumConsistency() {
        const enums = [
            { collection: 'users', field: 'role', validValues: ['user', 'admin'] },
            { collection: 'invitations', field: 'status', validValues: ['active', 'used', 'expired'] }
        ];
        
        const consistency = {};
        
        for (const enumCheck of enums) {
            try {
                const invalidValues = await this.db.collection(enumCheck.collection)
                    .find({ 
                        [enumCheck.field]: { 
                            $exists: true,
                            $nin: enumCheck.validValues 
                        }
                    })
                    .count();
                
                consistency[`${enumCheck.collection}.${enumCheck.field}`] = {
                    invalidCount: invalidValues,
                    isConsistent: invalidValues === 0,
                    validValues: enumCheck.validValues
                };
                
            } catch (error) {
                this.addError(
                    'ENUM_CONSISTENCY_CHECK_ERROR',
                    `Erreur de vérification de cohérence des énumérations ${enumCheck.collection}.${enumCheck.field}: ${error.message}`
                );
            }
        }
        
        return consistency;
    }

    /**
     * Évaluation de la précision
     */
    async assessAccuracy(accuracyResult) {
        // Précision des emails
        const emailAccuracy = await this.checkEmailAccuracy();
        
        // Précision des tokens
        const tokenAccuracy = await this.checkTokenAccuracy();
        
        // Précision des dates
        const dateAccuracy = await this.checkDateAccuracy();
        
        accuracyResult.emails = emailAccuracy;
        accuracyResult.tokens = tokenAccuracy;
        accuracyResult.dates = dateAccuracy;
    }

    /**
     * Vérification de la précision des emails
     */
    async checkEmailAccuracy() {
        const users = await this.db.collection('users')
            .find({ email: { $exists: true } })
            .project({ email: 1 })
            .toArray();
        
        let validEmails = 0;
        
        for (const user of users) {
            if (this.validateEmail(user.email)) {
                validEmails++;
            }
        }
        
        return {
            total: users.length,
            valid: validEmails,
            accuracy: users.length > 0 ? (validEmails / users.length) * 100 : 100
        };
    }

    /**
     * Vérification de la précision des tokens
     */
    async checkTokenAccuracy() {
        const invitations = await this.db.collection('invitations')
            .find({ token: { $exists: true } })
            .project({ token: 1 })
            .toArray();
        
        let validTokens = 0;
        
        for (const invitation of invitations) {
            if (this.validateToken(invitation.token)) {
                validTokens++;
            }
        }
        
        return {
            total: invitations.length,
            valid: validTokens,
            accuracy: invitations.length > 0 ? (validTokens / invitations.length) * 100 : 100
        };
    }

    /**
     * Vérification de la précision des dates
     */
    async checkDateAccuracy() {
        const collections = ['users', 'submissions', 'invitations', 'responses'];
        const dateFields = {
            users: ['metadata.registeredAt'],
            submissions: ['submittedAt'],
            invitations: ['createdAt', 'expiresAt'],
            responses: ['createdAt']
        };
        
        const accuracy = {};
        
        for (const collection of collections) {
            for (const field of dateFields[collection] || []) {
                const documents = await this.db.collection(collection)
                    .find({ [field]: { $exists: true } })
                    .project({ [field]: 1 })
                    .toArray();
                
                let validDates = 0;
                
                for (const doc of documents) {
                    const value = this.getNestedValue(doc, field);
                    if (value instanceof Date || !isNaN(Date.parse(value))) {
                        validDates++;
                    }
                }
                
                accuracy[`${collection}.${field}`] = {
                    total: documents.length,
                    valid: validDates,
                    accuracy: documents.length > 0 ? (validDates / documents.length) * 100 : 100
                };
            }
        }
        
        return accuracy;
    }

    /**
     * Calcul de la qualité globale
     */
    calculateOverallQuality(qualityResults) {
        let totalScore = 0;
        let categoryCount = 0;
        
        // Score de complétude
        const completenessScores = [];
        for (const collection of Object.values(qualityResults.completeness)) {
            for (const field of Object.values(collection)) {
                completenessScores.push(field.percentage);
            }
        }
        if (completenessScores.length > 0) {
            totalScore += completenessScores.reduce((a, b) => a + b, 0) / completenessScores.length;
            categoryCount++;
        }
        
        // Score de cohérence
        let consistencyScore = 100;
        for (const category of Object.values(qualityResults.consistency)) {
            for (const check of Object.values(category)) {
                if (!check.isConsistent) {
                    consistencyScore -= 10; // Pénalité pour chaque incohérence
                }
            }
        }
        if (categoryCount >= 0) {
            totalScore += Math.max(0, consistencyScore);
            categoryCount++;
        }
        
        // Score de précision
        const accuracyScores = [];
        for (const category of Object.values(qualityResults.accuracy)) {
            if (typeof category === 'object' && category.accuracy !== undefined) {
                accuracyScores.push(category.accuracy);
            } else {
                for (const check of Object.values(category)) {
                    if (check.accuracy !== undefined) {
                        accuracyScores.push(check.accuracy);
                    }
                }
            }
        }
        if (accuracyScores.length > 0) {
            totalScore += accuracyScores.reduce((a, b) => a + b, 0) / accuracyScores.length;
            categoryCount++;
        }
        
        return {
            overallScore: categoryCount > 0 ? totalScore / categoryCount : 0,
            completenessAvg: completenessScores.length > 0 ? completenessScores.reduce((a, b) => a + b, 0) / completenessScores.length : 100,
            consistencyScore: Math.max(0, consistencyScore),
            accuracyAvg: accuracyScores.length > 0 ? accuracyScores.reduce((a, b) => a + b, 0) / accuracyScores.length : 100
        };
    }

    /**
     * Comptage total des validations
     */
    getTotalValidationCount() {
        let total = 0;
        
        for (const category of Object.values(this.results)) {
            if (typeof category === 'object' && category !== null) {
                total += Object.keys(category).length;
            }
        }
        
        return total;
    }

    /**
     * Comptage des validations réussies
     */
    getPassedValidationCount() {
        let passed = 0;
        
        // Comptage basé sur l'absence d'erreurs dans chaque catégorie
        if (Object.keys(this.results.schemaValidation).every(col => 
            this.results.schemaValidation[col].valid)) {
            passed++;
        }
        
        if (Object.keys(this.results.dataTypeValidation).every(col => 
            this.results.dataTypeValidation[col].typeErrors.length === 0)) {
            passed++;
        }
        
        if (Object.keys(this.results.nullValidation).every(col => 
            this.results.nullValidation[col].nullViolations.length === 0)) {
            passed++;
        }
        
        if (Object.keys(this.results.encodingValidation).every(col => 
            this.results.encodingValidation[col].encodingErrors.length === 0)) {
            passed++;
        }
        
        if (Object.keys(this.results.constraintValidation).every(col => 
            this.results.constraintValidation[col].constraintViolations.length === 0)) {
            passed++;
        }
        
        return passed;
    }

    /**
     * Calcul du score final
     */
    calculateScore() {
        let score = 100;
        
        // Pénalités par type d'erreur
        const penalties = {
            'INVALID_DOCUMENT_SCHEMA': 8,
            'INVALID_DATA_TYPE': 6,
            'NULL_REQUIRED_FIELD': 10,
            'ENCODING_ISSUE': 4,
            'CONSTRAINT_VIOLATION': 7
        };
        
        // Application des pénalités
        for (const error of this.errors) {
            const penalty = penalties[error.code] || 5;
            score -= penalty;
        }
        
        // Bonus pour la qualité des données
        if (this.results.dataQuality && this.results.dataQuality.overall) {
            const qualityScore = this.results.dataQuality.overall.overallScore;
            if (qualityScore >= 95) {
                score += 10;
            } else if (qualityScore >= 90) {
                score += 5;
            }
        }
        
        return Math.max(0, Math.min(100, score));
    }
}

module.exports = DataValidator;