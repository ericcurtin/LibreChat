const express = require('express');
const mongoose = require('mongoose');
const {
  createCodeEnvironmentRegistry,
  createCodeEnvironmentHttpHandlers,
} = require('@librechat/api');
const { SystemCapabilities } = require('@librechat/data-schemas');
const { requireCapability } = require('~/server/middleware/roles/capabilities');
const { getAppConfig } = require('~/server/services/Config');
const { requireJwtAuth } = require('~/server/middleware');
const codeEnvironmentPairingLimiter = require('~/server/middleware/limiters/codeEnvironmentPairingLimiter');
const db = require('~/models');

const router = express.Router();
const registry = createCodeEnvironmentRegistry(mongoose);
const handlers = createCodeEnvironmentHttpHandlers({
  getAppConfig,
  registry,
  principalIsActive: db.isAgentTriggerPrincipalActive,
});
const requireCodeEnvironmentManage = requireCapability(SystemCapabilities.MANAGE_CODE_ENVIRONMENTS);

router.use(requireJwtAuth);
router.get('/', handlers.list);
router.post('/pairings', codeEnvironmentPairingLimiter, handlers.pair);
router.post('/', requireCodeEnvironmentManage, handlers.register);
router.delete('/:environmentId', handlers.remove);

module.exports = router;
