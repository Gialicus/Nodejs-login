export function checkPermission(user: any) {
    if (!user) return false
    if (user.role != 'ROLE_ADMIN') return false
    return true
}