const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const NotificationSchema = new Schema({
  // Recipient of the notification
  recipientId: { 
    type: Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  
  // Type of notification
  type: {
    type: String,
    enum: [
      'handshake_request',
      'handshake_accepted', 
      'handshake_declined',
      'handshake_expired',
      'contact_suggestion',
      'system_announcement'
    ],
    required: true,
    index: true
  },
  
  // Notification title and message
  title: { 
    type: String, 
    required: true,
    maxlength: 200
  },
  message: { 
    type: String, 
    required: true,
    maxlength: 1000
  },
  
  // Related entities
  relatedHandshakeId: { 
    type: Schema.Types.ObjectId, 
    ref: 'Handshake',
    index: true,
    sparse: true
  },
  relatedContactId: { 
    type: Schema.Types.ObjectId, 
    ref: 'Contact',
    sparse: true
  },
  relatedUserId: { 
    type: Schema.Types.ObjectId, 
    ref: 'User',
    sparse: true
  },
  
  // Notification state
  status: {
    type: String,
    enum: ['unread', 'read', 'archived'],
    default: 'unread',
    index: true
  },
  
  // Priority level
  priority: {
    type: String,
    enum: ['low', 'normal', 'high', 'urgent'],
    default: 'normal',
    index: true
  },
  
  // Action metadata for quick actions
  actionData: {
    handshakeId: String,
    actionType: String, // accept, decline, view, etc.
    requiresConfirmation: { type: Boolean, default: false },
    expiresAt: Date
  },
  
  // Delivery tracking
  delivery: {
    isDelivered: { type: Boolean, default: false },
    deliveredAt: Date,
    readAt: Date,
    clickedAt: Date,
    
    // Browser notification support
    browserNotificationSent: { type: Boolean, default: false },
    browserNotificationId: String
  },
  
  // Metadata
  metadata: {
    source: { 
      type: String, 
      enum: ['system', 'user_action', 'automated', 'admin'],
      default: 'system'
    },
    category: String, // grouping notifications
    displayUntil: Date, // auto-archive date
    requiresAction: { type: Boolean, default: false },
    isActionable: { type: Boolean, default: false }
  }
}, {
  timestamps: true
});

// Compound indexes for efficient queries
NotificationSchema.index({ recipientId: 1, status: 1, createdAt: -1 });
NotificationSchema.index({ recipientId: 1, type: 1, status: 1 });
NotificationSchema.index({ recipientId: 1, priority: 1, createdAt: -1 });
// Index removed to avoid duplicate with field-level sparse: true option

// Index for cleanup operations
NotificationSchema.index({ 
  status: 1, 
  'metadata.displayUntil': 1 
});

// Instance methods
NotificationSchema.methods.markAsRead = function() {
  this.status = 'read';
  this.delivery.readAt = new Date();
  this.delivery.isDelivered = true;
  if (!this.delivery.deliveredAt) {
    this.delivery.deliveredAt = new Date();
  }
  return this.save();
};

NotificationSchema.methods.markAsClicked = function() {
  if (!this.delivery.clickedAt) {
    this.delivery.clickedAt = new Date();
  }
  if (this.status === 'unread') {
    return this.markAsRead();
  }
  return this.save();
};

NotificationSchema.methods.archive = function() {
  this.status = 'archived';
  return this.save();
};

NotificationSchema.methods.isExpired = function() {
  if (this.actionData?.expiresAt) {
    return new Date() > this.actionData.expiresAt;
  }
  if (this.metadata?.displayUntil) {
    return new Date() > this.metadata.displayUntil;
  }
  return false;
};

NotificationSchema.methods.toClientJSON = function() {
  return {
    id: this._id,
    type: this.type,
    title: this.title,
    message: this.message,
    status: this.status,
    priority: this.priority,
    createdAt: this.createdAt,
    readAt: this.delivery?.readAt,
    actionData: this.actionData,
    metadata: this.metadata,
    relatedHandshakeId: this.relatedHandshakeId,
    relatedContactId: this.relatedContactId,
    relatedUserId: this.relatedUserId,
    isExpired: this.isExpired(),
    isActionable: this.metadata?.isActionable || false
  };
};

// Static methods
NotificationSchema.statics.createHandshakeNotification = async function(type, recipientId, handshake, options = {}) {
  const notificationData = {
    recipientId,
    type,
    relatedHandshakeId: handshake._id,
    relatedUserId: type === 'handshake_request' ? handshake.requesterId : handshake.targetId,
    priority: options.priority || 'normal',
    metadata: {
      source: 'user_action',
      category: 'handshake',
      isActionable: type === 'handshake_request',
      requiresAction: type === 'handshake_request',
      displayUntil: options.displayUntil || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
    }
  };

  // Set notification content based on type
  switch (type) {
    case 'handshake_request':
      notificationData.title = 'Nouvelle demande de handshake';
      notificationData.message = `${handshake.requesterId?.username || 'Un utilisateur'} vous a envoyé une demande de handshake`;
      notificationData.actionData = {
        handshakeId: handshake._id.toString(),
        actionType: 'handshake_response',
        requiresConfirmation: false,
        expiresAt: handshake.expiresAt
      };
      notificationData.priority = 'high';
      break;
      
    case 'handshake_accepted':
      notificationData.title = 'Handshake accepté';
      notificationData.message = `${handshake.targetId?.username || 'L\'utilisateur'} a accepté votre demande de handshake`;
      notificationData.priority = 'normal';
      break;
      
    case 'handshake_declined':
      notificationData.title = 'Handshake refusé';
      notificationData.message = `${handshake.targetId?.username || 'L\'utilisateur'} a refusé votre demande de handshake`;
      notificationData.priority = 'normal';
      break;
      
    case 'handshake_expired':
      notificationData.title = 'Handshake expiré';
      notificationData.message = 'Une demande de handshake a expiré';
      notificationData.priority = 'low';
      break;
  }

  return this.create(notificationData);
};

NotificationSchema.statics.getUserNotifications = async function(userId, options = {}) {
  const {
    status = null,
    type = null,
    page = 1,
    limit = 20,
    includeRead = true,
    includePriority = null
  } = options;

  const query = { recipientId: userId };
  
  if (status) {
    query.status = status;
  } else if (!includeRead) {
    query.status = { $ne: 'read' };
  }
  
  if (type) {
    query.type = type;
  }
  
  if (includePriority) {
    query.priority = includePriority;
  }

  const skip = (page - 1) * limit;
  
  const [notifications, totalCount] = await Promise.all([
    this.find(query)
      .populate('relatedUserId', 'username email')
      .populate('relatedHandshakeId')
      .sort({ priority: -1, createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean(),
    
    this.countDocuments(query)
  ]);

  return {
    notifications,
    pagination: {
      page,
      limit,
      totalCount,
      totalPages: Math.ceil(totalCount / limit),
      hasNext: page < Math.ceil(totalCount / limit),
      hasPrev: page > 1
    }
  };
};

NotificationSchema.statics.getUnreadCounts = async function(userId) {
  const counts = await this.aggregate([
    { $match: { recipientId: userId, status: 'unread' } },
    {
      $group: {
        _id: '$type',
        count: { $sum: 1 },
        highPriorityCount: {
          $sum: { $cond: [{ $in: ['$priority', ['high', 'urgent']] }, 1, 0] }
        }
      }
    }
  ]);

  const result = {
    total: 0,
    handshake_request: 0,
    handshake_accepted: 0,
    handshake_declined: 0,
    contact_suggestion: 0,
    system_announcement: 0,
    highPriorityTotal: 0
  };

  counts.forEach(item => {
    result[item._id] = item.count;
    result.total += item.count;
    result.highPriorityTotal += item.highPriorityCount;
  });

  return result;
};

NotificationSchema.statics.markAllAsRead = async function(userId, type = null) {
  const query = { 
    recipientId: userId, 
    status: 'unread' 
  };
  
  if (type) {
    query.type = type;
  }

  const updateData = {
    status: 'read',
    'delivery.readAt': new Date(),
    'delivery.isDelivered': true
  };

  return this.updateMany(query, updateData);
};

NotificationSchema.statics.cleanupOldNotifications = async function(daysOld = 30) {
  const cutoffDate = new Date(Date.now() - daysOld * 24 * 60 * 60 * 1000);
  
  // Archive old read notifications
  const archivedResult = await this.updateMany(
    {
      status: 'read',
      'delivery.readAt': { $lt: cutoffDate }
    },
    { status: 'archived' }
  );

  // Delete very old archived notifications
  const veryOldDate = new Date(Date.now() - (daysOld * 2) * 24 * 60 * 60 * 1000);
  const deletedResult = await this.deleteMany({
    status: 'archived',
    updatedAt: { $lt: veryOldDate }
  });

  return {
    archived: archivedResult.modifiedCount,
    deleted: deletedResult.deletedCount
  };
};

module.exports = mongoose.models.Notification || mongoose.model('Notification', NotificationSchema);