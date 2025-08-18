const crypto = require('crypto');
const Response = require('../models/Response');
const EnvironmentConfig = require('../config/environment');
const { APP_CONSTANTS } = require('../constants');
const TokenGenerator = require('../utils/tokenGenerator');
const { sanitizeMongoInput, sanitizeObjectId, logSecurityEvent } = require('../middleware/querySanitization');

class ResponseService {
  static generateToken() {
    return TokenGenerator.generateResponseToken();
  }

  static getCurrentMonth() {
    return new Date().toISOString().slice(0, 7); // "YYYY-MM"
  }

  static isAdminUser(name) {
    const config = EnvironmentConfig.getConfig();
    return name.trim().toLowerCase() === config.admin.formName?.toLowerCase();
  }

  static async checkAdminExists(month) {
    const sanitizedMonth = sanitizeMongoInput(month);
    return await Response.exists({ month: sanitizedMonth, isAdmin: true });
  }

  static async createResponse(data) {
    const { name, responses } = data;
    const month = this.getCurrentMonth();
    const isAdmin = this.isAdminUser(name);
    
    // Vérifier si admin existe déjà pour ce mois
    if (isAdmin) {
      const adminExists = await this.checkAdminExists(month);
      if (adminExists) {
        throw new Error('Une réponse admin existe déjà pour ce mois.');
      }
    }

    const token = isAdmin ? undefined : this.generateToken();

    const newResponse = new Response({
      name,
      responses,
      month,
      isAdmin,
      token
    });

    await newResponse.save();

    const config = EnvironmentConfig.getConfig();
    const link = token ? `${config.urls.appBase}/view/${token}` : null;

    return {
      response: newResponse,
      link
    };
  }

  static async getResponseByToken(token) {
    const sanitizedToken = sanitizeMongoInput(token);
    
    if (!sanitizedToken || typeof sanitizedToken !== 'string') {
      logSecurityEvent('INVALID_TOKEN_ACCESS_ATTEMPT', { 
        token: typeof token === 'string' ? token.substring(0, 10) + '...' : typeof token
      });
      return null;
    }
    
    const userResp = await Response.findOne({ token: sanitizedToken, isAdmin: false }).lean();
    if (!userResp) {
      return null;
    }

    const adminResp = await Response.findOne({ 
      month: sanitizeMongoInput(userResp.month), 
      isAdmin: true 
    }).lean();

    return {
      user: userResp,
      admin: adminResp
    };
  }

  static async getAllResponses(page = 1, limit = APP_CONSTANTS.DEFAULT_PAGE_SIZE || 10, sortBy = 'createdAt', sortOrder = 'desc') {
    // Sanitize and validate input parameters
    const sanitizedPage = Math.max(1, parseInt(page, 10) || 1);
    const sanitizedLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 10));
    const sanitizedSortBy = sanitizeMongoInput(sortBy);
    const sanitizedSortOrder = sanitizeMongoInput(sortOrder);
    
    // Whitelist allowed sort fields
    const allowedSortFields = ['createdAt', 'month', 'name', 'isAdmin'];
    const finalSortBy = allowedSortFields.includes(sanitizedSortBy) ? sanitizedSortBy : 'createdAt';
    const finalSortOrder = ['asc', 'desc'].includes(sanitizedSortOrder) ? sanitizedSortOrder : 'desc';
    
    const skip = (sanitizedPage - 1) * sanitizedLimit;
    const sort = { [finalSortBy]: finalSortOrder === 'desc' ? -1 : 1 };

    const responses = await Response.find()
      .sort(sort)
      .skip(skip)
      .limit(sanitizedLimit)
      .lean();

    const total = await Response.countDocuments();
    const totalPages = Math.ceil(total / sanitizedLimit);

    return {
      responses,
      pagination: {
        currentPage: sanitizedPage,
        totalPages,
        totalResponses: total,
        hasNextPage: sanitizedPage < totalPages,
        hasPrevPage: sanitizedPage > 1
      }
    };
  }

  static async getResponsesSummary() {
    const pipeline = [
      {
        $group: {
          _id: {
            month: '$month',
            isAdmin: '$isAdmin'
          },
          count: { $sum: 1 },
          names: { $push: '$name' }
        }
      },
      {
        $group: {
          _id: '$_id.month',
          admin: {
            $push: {
              $cond: [
                { $eq: ['$_id.isAdmin', true] },
                { count: '$count', names: '$names' },
                null
              ]
            }
          },
          users: {
            $push: {
              $cond: [
                { $eq: ['$_id.isAdmin', false] },
                { count: '$count', names: '$names' },
                null
              ]
            }
          }
        }
      },
      {
        $sort: { _id: -1 }
      }
    ];

    return await Response.aggregate(pipeline);
  }

  static async getResponseById(id) {
    const sanitizedId = sanitizeObjectId(id);
    
    if (!sanitizedId) {
      logSecurityEvent('INVALID_RESPONSE_ID_ACCESS', { 
        id: typeof id === 'string' ? id.substring(0, 10) + '...' : typeof id
      });
      return null;
    }
    
    return await Response.findById(sanitizedId).lean();
  }

  static async deleteResponse(id) {
    const sanitizedId = sanitizeObjectId(id);
    
    if (!sanitizedId) {
      logSecurityEvent('INVALID_RESPONSE_DELETE_ATTEMPT', { 
        id: typeof id === 'string' ? id.substring(0, 10) + '...' : typeof id
      });
      throw new Error('Invalid response ID provided');
    }
    
    const deleted = await Response.findByIdAndDelete(sanitizedId);
    
    if (deleted) {
      logSecurityEvent('RESPONSE_DELETED', { 
        responseId: sanitizedId,
        deletedName: deleted.name?.substring(0, 10) + '...',
        deletedMonth: deleted.month
      }, 'low');
    }
    
    return deleted;
  }

  static async getAvailableMonths() {
    const mongoose = require('mongoose');
    
    const pipeline = [
      { $project: { year: { $year: '$createdAt' }, month: { $month: '$createdAt' } } },
      { $group:   { _id: { y: '$year', m: '$month' } } },
      { $sort:    { '_id.y': -1, '_id.m': -1 } },
      { $project: {
          _id: 0,
          key: {
            $concat: [
              { $toString: '$_id.y' }, '-',
              { $cond: [
                { $lt: ['$_id.m', 10] },
                { $concat: ['0', { $toString: '$_id.m' }] },
                { $toString: '$_id.m' }
              ] }
            ]
          },
          label: {
            $concat: [
              { $arrayElemAt: [[
                'janvier','février','mars','avril','mai','juin',
                'juillet','août','septembre','octobre','novembre','décembre'
              ], { $subtract: ['$_id.m', 1] }] },
              ' ',
              { $toString: '$_id.y' }
            ]
          }
      }}
    ];

    return await mongoose.connection.db
      .collection('responses')
      .aggregate(pipeline, { allowDiskUse: true })
      .toArray();
  }
}

module.exports = ResponseService;