/*
 * adduser  –  Add/update a user in the sshmini credential store (users.db)
 *
 * Usage:  ./adduser <username> <password>
 */
#include <stdio.h>
#include <stdlib.h>
#include "auth.h"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <username> <password>\n", argv[0]);
        return 1;
    }
    if (auth_add_user(argv[1], argv[2]) == 0) {
        printf("User '%s' added/updated in %s\n", argv[1], USERS_DB);
        return 0;
    } else {
        fprintf(stderr, "Failed to write to %s\n", USERS_DB);
        return 1;
    }
}
