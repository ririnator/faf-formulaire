const crypto = require('crypto');
const Response = require('../models/Response');

class ResponseService {
  constructor(config) {
    this.config = config;
  }

  generateToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  getCurrentMonth() {
    return new Date().toISOString().slice(0, 7); // "YYYY-MM"
  }

  isAdminUser(name) {
    return name.trim().toLowerCase() === this.config.admin.formName?.toLowerCase();
  }

  async checkAdminExists(month) {
    return await Response.exists({ month, isAdmin: true });
  }

  async createResponse(data) {
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

    const link = token ? `${this.config.urls.appBase}/view/${token}` : null;

    return {
      response: newResponse,
      link
    };
  }

  async getResponseByToken(token) {
    const userResp = await Response.findOne({ token, isAdmin: false }).lean();
    if (!userResp) {
      return null;
    }

    const adminResp = await Response.findOne({ 
      month: userResp.month, 
      isAdmin: true 
    }).lean();

    return {
      user: userResp,
      admin: adminResp
    };
  }

  async getAllResponses(page = 1, limit = 10, sortBy = 'createdAt', sortOrder = 'desc') {
    const skip = (page - 1) * limit;
    const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

    const responses = await Response.find()
      .sort(sort)
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Response.countDocuments();
    const totalPages = Math.ceil(total / limit);

    return {
      responses,
      pagination: {
        currentPage: page,
        totalPages,
        totalResponses: total,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1
      }
    };
  }

  async getResponsesSummary() {
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

  async getResponseById(id) {
    return await Response.findById(id).lean();
  }

  async deleteResponse(id) {
    const deleted = await Response.findByIdAndDelete(id);
    return deleted;
  }

  async getAvailableMonths() {
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