# API SPECIFICATIONS

### User Endpoints

/api/auth/register
/api/auth/login
/api/auth/confirm-email
/api/auth/reset-password
/api/users/me
/api/users/avatar
/api/games
/api/games/{gameId}/save
/api/games/{gameId}/load
/api/games/{gameId}/leaderboard
/api/games/{gameId}/packages
/api/games/{gameId}/purchase/{packageId}

### Admin Endpoints

/api/admin/users
/api/admin/users/{userId}
/api/admin/games
/api/admin/games/{gameId}
/api/admin/packages
/api/admin/packages/{packageId}
/api/admin/transactions
/api/admin/dashboard
/api/admin/export/transactions
/api/admin/audit-logs
