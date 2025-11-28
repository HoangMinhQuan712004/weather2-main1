const mongoose = require('mongoose');

const securityEventSchema = new mongoose.Schema({
  type: {
    type: String,
    required: true
  },
  severity: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  ip: String,
  userAgent: String,
  method: String,
  path: String,
  query: String,
  message: String,
  details: String,
  ruleId: String,
  blocked: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

securityEventSchema.index({ createdAt: -1 });
securityEventSchema.index({ ip: 1 });
securityEventSchema.index({ type: 1 });

// Auto-delete after 30 days
securityEventSchema.index({ createdAt: 1 }, { expireAfterSeconds: 2592000 });

module.exports = mongoose.model('SecurityEvent', securityEventSchema);
