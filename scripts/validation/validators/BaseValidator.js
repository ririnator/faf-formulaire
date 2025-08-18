/**
 * Classe de base pour tous les validateurs
 * 
 * Fournit les fonctionnalités communes pour la validation d'intégrité :
 * - Gestion des erreurs standardisée
 * - Logging uniforme
 * - Utilitaires de validation
 * - Interface commune
 * 
 * @author FAF Migration Team
 */

class BaseValidator {
    constructor(name, db, logger) {
        this.name = name;
        this.db = db;
        this.logger = logger;
        this.errors = [];
        this.warnings = [];
        this.startTime = null;
    }

    /**
     * Méthode de validation principale (à implémenter par les sous-classes)
     */
    async validate() {
        throw new Error('La méthode validate() doit être implémentée par la sous-classe');
    }

    /**
     * Ajout d'une erreur
     */
    addError(code, message, context = {}) {
        const error = {
            code,
            message,
            context,
            timestamp: new Date().toISOString(),
            validator: this.name
        };
        
        this.errors.push(error);
        this.logger.error(`❌ ${code}: ${message}`, context);
    }

    /**
     * Ajout d'un avertissement
     */
    addWarning(code, message, context = {}) {
        const warning = {
            code,
            message,
            context,
            timestamp: new Date().toISOString(),
            validator: this.name
        };
        
        this.warnings.push(warning);
        this.logger.warn(`⚠️ ${code}: ${message}`, context);
    }

    /**
     * Validation de l'existence d'une collection
     */
    async validateCollectionExists(collectionName) {
        try {
            const collections = await this.db.listCollections().toArray();
            const exists = collections.some(c => c.name === collectionName);
            
            if (!exists) {
                this.addError(
                    'COLLECTION_NOT_FOUND',
                    `Collection manquante: ${collectionName}`
                );
                return false;
            }
            
            return true;
        } catch (error) {
            this.addError(
                'COLLECTION_CHECK_FAILED',
                `Impossible de vérifier l'existence de la collection ${collectionName}: ${error.message}`
            );
            return false;
        }
    }

    /**
     * Validation de la structure d'un document
     */
    validateDocumentStructure(document, requiredFields, documentType = 'document') {
        const missingFields = [];
        const invalidFields = [];
        
        for (const field of requiredFields) {
            if (typeof field === 'string') {
                // Champ simple
                if (!(field in document)) {
                    missingFields.push(field);
                }
            } else if (typeof field === 'object') {
                // Champ avec validation de type
                const { name, type, required = true } = field;
                
                if (!(name in document)) {
                    if (required) {
                        missingFields.push(name);
                    }
                } else {
                    const value = document[name];
                    if (!this.validateFieldType(value, type)) {
                        invalidFields.push({ name, expectedType: type, actualType: typeof value });
                    }
                }
            }
        }
        
        if (missingFields.length > 0) {
            this.addError(
                'MISSING_FIELDS',
                `Champs manquants dans ${documentType}: ${missingFields.join(', ')}`,
                { documentId: document._id, missingFields }
            );
        }
        
        if (invalidFields.length > 0) {
            this.addError(
                'INVALID_FIELD_TYPES',
                `Types de champs invalides dans ${documentType}`,
                { documentId: document._id, invalidFields }
            );
        }
        
        return missingFields.length === 0 && invalidFields.length === 0;
    }

    /**
     * Validation du type d'un champ
     */
    validateFieldType(value, expectedType) {
        if (value === null || value === undefined) {
            return expectedType.includes('null') || expectedType.includes('undefined');
        }
        
        const actualType = typeof value;
        
        if (Array.isArray(expectedType)) {
            return expectedType.includes(actualType);
        }
        
        if (expectedType === 'array') {
            return Array.isArray(value);
        }
        
        if (expectedType === 'date') {
            return value instanceof Date || !isNaN(Date.parse(value));
        }
        
        if (expectedType === 'objectId') {
            return this.isValidObjectId(value);
        }
        
        return actualType === expectedType;
    }

    /**
     * Validation d'un ObjectId MongoDB
     */
    isValidObjectId(id) {
        if (!id) return false;
        
        // Vérification du format ObjectId
        const objectIdRegex = /^[0-9a-fA-F]{24}$/;
        return objectIdRegex.test(id.toString());
    }

    /**
     * Calcul d'un hash pour détecter les doublons
     */
    calculateDocumentHash(document, fields) {
        const crypto = require('crypto');
        const values = fields.map(field => {
            const value = this.getNestedValue(document, field);
            return JSON.stringify(value);
        }).join('|');
        
        return crypto.createHash('md5').update(values).digest('hex');
    }

    /**
     * Obtention d'une valeur imbriquée dans un objet
     */
    getNestedValue(obj, path) {
        return path.split('.').reduce((current, key) => {
            return current && current[key] !== undefined ? current[key] : undefined;
        }, obj);
    }

    /**
     * Validation de la cohérence temporelle
     */
    validateTimestamps(timestamps, tolerance = 60000) {
        if (timestamps.length < 2) return true;
        
        const sortedTimestamps = timestamps
            .map(ts => new Date(ts).getTime())
            .filter(ts => !isNaN(ts))
            .sort();
        
        for (let i = 1; i < sortedTimestamps.length; i++) {
            const diff = Math.abs(sortedTimestamps[i] - sortedTimestamps[i - 1]);
            if (diff > tolerance) {
                return false;
            }
        }
        
        return true;
    }

    /**
     * Validation d'un email
     */
    validateEmail(email) {
        if (!email || typeof email !== 'string') return false;
        
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    /**
     * Validation d'un nom d'utilisateur
     */
    validateUsername(username) {
        if (!username || typeof username !== 'string') return false;
        
        // Critères : 3-30 caractères, alphanumériques et underscores
        const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
        return usernameRegex.test(username);
    }

    /**
     * Validation d'un token
     */
    validateToken(token) {
        if (!token || typeof token !== 'string') return false;
        
        // Les tokens doivent être des chaînes non vides
        return token.length > 0 && token.length <= 255;
    }

    /**
     * Création d'un rapport de progression
     */
    createProgressReport(current, total, operation = 'validation') {
        const percentage = total > 0 ? ((current / total) * 100).toFixed(1) : 0;
        return {
            current,
            total,
            percentage: parseFloat(percentage),
            operation,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Mesure du temps d'exécution
     */
    startTimer() {
        this.startTime = Date.now();
    }

    /**
     * Fin de la mesure du temps
     */
    endTimer() {
        if (!this.startTime) return 0;
        return Date.now() - this.startTime;
    }

    /**
     * Validation d'une contrainte d'unicité
     */
    async validateUniqueness(collection, field, value, excludeId = null) {
        try {
            const query = { [field]: value };
            if (excludeId) {
                query._id = { $ne: excludeId };
            }
            
            const count = await this.db.collection(collection).countDocuments(query);
            return count === 0;
            
        } catch (error) {
            this.addError(
                'UNIQUENESS_CHECK_FAILED',
                `Échec de la vérification d'unicité pour ${field}: ${error.message}`
            );
            return false;
        }
    }

    /**
     * Validation d'une référence
     */
    async validateReference(fromCollection, fromField, toCollection, toField = '_id') {
        try {
            const pipeline = [
                {
                    $lookup: {
                        from: toCollection,
                        localField: fromField,
                        foreignField: toField,
                        as: 'referenced'
                    }
                },
                {
                    $match: {
                        [fromField]: { $ne: null },
                        referenced: { $size: 0 }
                    }
                },
                {
                    $project: {
                        [fromField]: 1
                    }
                }
            ];
            
            const orphans = await this.db.collection(fromCollection).aggregate(pipeline).toArray();
            
            if (orphans.length > 0) {
                this.addError(
                    'ORPHANED_REFERENCES',
                    `Références orphelines trouvées: ${orphans.length} documents dans ${fromCollection}`,
                    { orphans: orphans.slice(0, 10) } // Limite pour éviter les gros logs
                );
                return false;
            }
            
            return true;
            
        } catch (error) {
            this.addError(
                'REFERENCE_CHECK_FAILED',
                `Échec de la vérification de référence ${fromCollection}.${fromField} → ${toCollection}.${toField}: ${error.message}`
            );
            return false;
        }
    }

    /**
     * Génération d'un résumé des erreurs
     */
    getErrorSummary() {
        const summary = {
            total: this.errors.length,
            byCode: {},
            bySeverity: { HIGH: 0, MEDIUM: 0, LOW: 0 }
        };
        
        for (const error of this.errors) {
            // Comptage par code
            summary.byCode[error.code] = (summary.byCode[error.code] || 0) + 1;
            
            // Classification par sévérité (basée sur le code)
            const severity = this.getErrorSeverity(error.code);
            summary.bySeverity[severity]++;
        }
        
        return summary;
    }

    /**
     * Détermination de la sévérité d'une erreur
     */
    getErrorSeverity(errorCode) {
        const highSeverityErrors = [
            'COLLECTION_NOT_FOUND',
            'MISSING_FIELDS',
            'ORPHANED_REFERENCES',
            'DUPLICATE_RESPONSE',
            'DUPLICATE_SUBMISSION',
            'USERNAME_DUPLICATE',
            'EMAIL_DUPLICATE'
        ];
        
        const mediumSeverityErrors = [
            'INVALID_FIELD_TYPES',
            'UNMATCHED_RESPONSE',
            'UNMATCHED_SUBMISSION',
            'ROLE_MISMATCH',
            'MONTHLY_MISMATCH'
        ];
        
        if (highSeverityErrors.includes(errorCode)) return 'HIGH';
        if (mediumSeverityErrors.includes(errorCode)) return 'MEDIUM';
        return 'LOW';
    }
}

module.exports = BaseValidator;