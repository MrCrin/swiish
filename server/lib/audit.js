const crypto = require('crypto');
const { db } = require('../db');

// Helper function to log audit events
async function logAudit(eventType, entityType, entityId, entityData, performedBy, organisationId) {
  const auditId = crypto.randomUUID();
  return new Promise((resolve, reject) => {
    db.run(
      "INSERT INTO audit_log (id, event_type, entity_type, entity_id, entity_data, performed_by, organisation_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [auditId, eventType, entityType, entityId, JSON.stringify(entityData), performedBy, organisationId],
      (err) => {
        if (err) {
          console.error('[AUDIT] Failed to log event:', err);
          reject(err);
        } else {
          resolve(auditId);
        }
      }
    );
  });
}

module.exports = {
  logAudit,
};
