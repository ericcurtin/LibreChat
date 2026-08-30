const rateLimit = require('express-rate-limit');
const { limiterCache } = require('@librechat/api');

const codeEnvironmentPairingLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  keyGenerator: (req) => req.user?.id,
  handler: (_req, res) => {
    res.status(429).json({ error: 'Too many code environment pairing requests' });
  },
  store: limiterCache('code_environment_pairing_limiter'),
});

module.exports = codeEnvironmentPairingLimiter;
