const SecurityEvent = require('../models/SecurityEvent');

const PATTERNS = [
  {
    type: 'SQL_INJECTION',
    rule: 'union-select',
    description: 'Phát hiện chuỗi UNION SELECT',
    regex: /union\s+select/i
  },
  {
    type: 'SQL_INJECTION',
    rule: 'or-equals',
    description: 'Phát hiện payload dạng \' OR \'1\'=\'1',
    regex: /('|%27)\s*or\s+('|%27)?1('|%27)?\s*=\s*('|%27)?1/i
  },
  {
    type: 'XSS',
    rule: 'script-tag',
    description: 'Thẻ script hoặc javascript: URI',
    regex: /<\s*script|javascript:/i
  },
  {
    type: 'PATH_TRAVERSAL',
    rule: 'dotdot',
    description: 'Chuỗi ../ hoặc ..\\',
    regex: /(\.\.\/)|(\.\.\\)|%2e%2e%2f|%2e%2e\\/i
  },
  {
    type: 'SSRF',
    rule: 'metadata-endpoint',
    description: 'Truy cập metadata hoặc localhost',
    regex: /(169\.254\.169\.254|metadata\/v1|localhost|127\.0\.0\.1)/i
  },
  {
    type: 'COMMAND_INJECTION',
    rule: 'command-chain',
    description: 'Chuỗi ;, &&, || kèm lệnh hệ thống',
    regex: /(;|&&|\|\|)\s*(cat|ls|whoami|id|curl|wget)\b/i
  }
];

const MAX_VALUE_LENGTH = 2000;
const INSPECTED_HEADERS = ['user-agent', 'referer'];
const SKIPPED_PATHS = [
  '/api/security/status',
  '/api/security/events',
  // XÓA '/api/weather/search' nếu bạn muốn chặn SQL Injection ở search
];
const AUTH_SAFE_PATHS = ['/api/auth/login', '/api/auth/register', '/api/auth/login/cccd'];

function extractEntries(data, prefix = '') {
  if (data === null || data === undefined) return [];

  if (typeof data === 'string') {
    return [{ key: prefix || 'value', value: data }];
  }

  if (typeof data === 'number' || typeof data === 'boolean') {
    return [{ key: prefix || 'value', value: String(data) }];
  }

  if (Array.isArray(data)) {
    return data.flatMap((item, index) => extractEntries(item, `${prefix}[${index}]`));
  }

  if (typeof data === 'object') {
    return Object.keys(data).flatMap((key) => extractEntries(data[key], prefix ? `${prefix}.${key}` : key));
  }

  return [];
}

async function logSecurityEvent(payload) {
  try {
    const event = new SecurityEvent(payload);
    await event.save();
    return event;
  } catch (err) {
    console.error('Không thể lưu security event:', err.message);
    return null;
  }
}

module.exports = async function attackMonitor(req, res, next) {
  try {
    if (SKIPPED_PATHS.includes(req.path)) {
      return next();
    }

    if (AUTH_SAFE_PATHS.includes(req.path) && req.method === 'POST') {
      const { email, username, password } = req.body || {};
      const isSimpleAuthPayload =
        (!email || typeof email === 'string') &&
        (!username || typeof username === 'string') &&
        (!password || typeof password === 'string');

      if (isSimpleAuthPayload) {
        return next();
      }
    }

    const entries = [
      ...extractEntries(req.query, 'query'),
      ...extractEntries(req.body, 'body'),
      ...extractEntries(req.params, 'params')
    ];

    for (const headerName of INSPECTED_HEADERS) {
      if (req.headers[headerName]) {
        entries.push({
          key: `headers.${headerName}`,
          value: req.headers[headerName]
        });
      }
    }

    entries.push({ key: 'path', value: req.originalUrl || req.url || req.path });

    for (const entry of entries) {
      const value = typeof entry.value === 'string'
        ? entry.value.slice(0, MAX_VALUE_LENGTH)
        : '';

      if (!value) continue;

      for (const pattern of PATTERNS) {
        if (pattern.regex.test(value)) {
          const eventPayload = {
            type: pattern.type,
            rule: pattern.rule,
            source: entry.key,
            method: req.method,
            path: req.path,
            ip: req.ip || req.connection?.remoteAddress,
            payload: value,
            headers: {
              'user-agent': req.headers['user-agent'],
              referer: req.headers.referer
            },
            meta: {
              description: pattern.description
            }
          };

          const event = await logSecurityEvent(eventPayload);

          return res.status(406).json({
            message: 'Yêu cầu bị chặn bởi lớp bảo mật tích hợp',
            reason: pattern.description,
            eventId: event?._id || null
          });
        }
      }
    }

    return next();
  } catch (error) {
    console.error('Attack monitor error:', error);
    return next();
  }
};

