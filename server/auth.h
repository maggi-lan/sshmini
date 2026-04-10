#ifndef AUTH_H
#define AUTH_H

/* ─── Simple credential store ─────────────────────────── */
/*
 * Credentials are stored in a flat file: users.db
 * Format (one entry per line):
 *   username:SHA256_HEX_OF_PASSWORD\n
 *
 * The server hashes the received password with SHA-256
 * and compares against the stored hash.
 */

#define USERS_DB  "users.db"

/*
 * Verify username + plaintext password against users.db.
 * Returns 1 on success, 0 on failure.
 */
int auth_verify(const char *username, const char *password);

/*
 * Add or update an entry in users.db (utility for setup).
 * Returns 0 on success, -1 on error.
 */
int auth_add_user(const char *username, const char *password);

#endif /* AUTH_H */
