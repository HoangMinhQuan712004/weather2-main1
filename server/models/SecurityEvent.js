const mongoose = require('mongoose');

const securityEventSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      required: true
    },
    rule: {
      type: String,
      required: true
    },
    source: {
      type: String,
      required: true
    },
    method: {
      type: String,
      required: true
    },
    path: {
      type: String,
      required: true
    },
    ip: String,
    payload: String,
    headers: {
      type: Object,
      default: {}
    },
    blocked: {
      type: Boolean,
      default: true
    },
    meta: {
      type: Object,
      default: {}
    }
  },
  {
    timestamps: true
  }
);

securityEventSchema.index({ createdAt: -1 });
securityEventSchema.index({ type: 1, createdAt: -1 });

module.exports = mongoose.model('SecurityEvent', securityEventSchema);

