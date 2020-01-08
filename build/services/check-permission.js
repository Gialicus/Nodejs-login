"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
function checkPermission(user) {
    if (!user)
        return false;
    if (user.role != 'ROLE_ADMIN')
        return false;
    return true;
}
exports.checkPermission = checkPermission;
