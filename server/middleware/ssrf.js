const dns = require('dns').promises;
const { URL } = require('url');
const net = require('net');

// Convert IPv4 string to integer
function ipv4ToInt(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function isPrivateIp(ip) {
  if (net.isIP(ip) === 4) {
    const i = ipv4ToInt(ip);
    // 10.0.0.0/8
    if (i >= ipv4ToInt('10.0.0.0') && i <= ipv4ToInt('10.255.255.255')) return true;
    // 172.16.0.0/12
    if (i >= ipv4ToInt('172.16.0.0') && i <= ipv4ToInt('172.31.255.255')) return true;
    // 192.168.0.0/16
    if (i >= ipv4ToInt('192.168.0.0') && i <= ipv4ToInt('192.168.255.255')) return true;
    // 127.0.0.0/8
    if (i >= ipv4ToInt('127.0.0.0') && i <= ipv4ToInt('127.255.255.255')) return true;
    // 169.254.0.0/16 (link-local)
    if (i >= ipv4ToInt('169.254.0.0') && i <= ipv4ToInt('169.254.255.255')) return true;
    return false;
  }
  // IPv6 checks (basic)
  if (net.isIP(ip) === 6) {
    if (ip === '::1') return true;
    const lower = ip.toLowerCase();
    if (lower.startsWith('fe80') || lower.startsWith('fc') || lower.startsWith('fd')) return true;
    return false;
  }
  return false;
}

async function resolveHostToIps(hostname) {
  try {
    const ips = [];
    // Try A and AAAA records
    try {
      const a = await dns.resolve4(hostname);
      ips.push(...a);
    } catch (e) {
      // ignore
    }
    try {
      const a6 = await dns.resolve6(hostname);
      ips.push(...a6);
    } catch (e) {
      // ignore
    }
    // As a fallback, do lookup which may return one record
    if (ips.length === 0) {
      try {
        const lookup = await dns.lookup(hostname, { all: true });
        for (const l of lookup) ips.push(l.address);
      } catch (e) {
        // ignore
      }
    }
    return ips;
  } catch (err) {
    return [];
  }
}

// Middleware: block requests that include a `url` parameter pointing to internal/private IPs
module.exports = function ssrfMiddleware(req, res, next) {
  // Only check when there is a url in query or body
  const target = (req.query && (req.query.url || req.query.to || req.query.next)) || (req.body && req.body.url);
  if (!target) return next();

  let parsed;
  try {
    parsed = new URL(target);
  } catch (e) {
    // Not a valid URL — allow the request to be handled by route if it expects paths
    return next();
  }

  const hostname = parsed.hostname;
  // If hostname is an IP literal, check immediately
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) return res.status(400).json({ error: 'Disallowed target address' });
    return next();
  }

  // Resolve DNS and check each IP
  resolveHostToIps(hostname).then((ips) => {
    for (const ip of ips) {
      if (isPrivateIp(ip)) {
        return res.status(400).json({ error: 'Disallowed target address' });
      }
    }
    return next();
  }).catch((err) => {
    // On DNS resolution errors, be conservative and block
    console.warn('SSRF resolver error:', err);
    return res.status(400).json({ error: 'Unable to validate target address' });
  });
};
