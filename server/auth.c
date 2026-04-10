#include "auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

/* ─── SHA-256 helper ──────────────────────────────────── */
static void sha256_hex(const char *input, char out_hex[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)input, strlen(input), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(out_hex + i*2, "%02x", hash[i]);
    out_hex[64] = '\0';
}

/* ─── Verify credentials ──────────────────────────────── */
int auth_verify(const char *username, const char *password) {
    FILE *fp = fopen(USERS_DB, "r");
    if (!fp) return 0;

    char line[512];
    char hash_input[65];
    sha256_hex(password, hash_input);

    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        /* strip newline */
        line[strcspn(line, "\r\n")] = '\0';
        char *sep = strchr(line, ':');
        if (!sep) continue;
        *sep = '\0';
        const char *stored_user = line;
        const char *stored_hash = sep + 1;

        if (strcmp(stored_user, username) == 0 &&
            strcmp(stored_hash, hash_input) == 0) {
            found = 1;
            break;
        }
    }
    fclose(fp);
    return found;
}

/* ─── Add / update user ───────────────────────────────── */
int auth_add_user(const char *username, const char *password) {
    /* Load existing entries except the one being replaced */
    FILE *fp = fopen(USERS_DB, "r");
    char lines[256][512];
    int  count = 0;

    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp) && count < 256) {
            line[strcspn(line, "\r\n")] = '\0';
            char *sep = strchr(line, ':');
            if (!sep) continue;
            *sep = '\0';
            if (strcmp(line, username) != 0) {
                /* restore separator */
                *sep = ':';
                strncpy(lines[count++], line, 511);
            }
        }
        fclose(fp);
    }

    /* Add new entry */
    char hash_buf[65];
    sha256_hex(password, hash_buf);

    fp = fopen(USERS_DB, "w");
    if (!fp) return -1;

    for (int i = 0; i < count; i++)
        fprintf(fp, "%s\n", lines[i]);
    fprintf(fp, "%s:%s\n", username, hash_buf);
    fclose(fp);
    return 0;
}
