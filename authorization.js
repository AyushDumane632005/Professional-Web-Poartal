'use strict';

const ROLES = Object.freeze(['employee', 'safety_manager', 'platform_admin', 'hq']);

function roleAllowed(role, allowedRoles) {
  return ROLES.includes(role) && allowedRoles.includes(role);
}

function sessionVersionMatches(tokenVersion, storedVersion) {
  return Number.isSafeInteger(tokenVersion) && Number(tokenVersion) === Number(storedVersion);
}

module.exports = { ROLES, roleAllowed, sessionVersionMatches };
