#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>



#define MAX_USERS 100
#define MAX_FILES 50
#define MAX_HOSTNAME_LENGTH 256
#define MAX_FINGERPRINT_LENGTH 256
#define MAX_MODIFICATIONS 100


struct log_entry {
    int uid; /* user id (positive integer) */
    int access_type; /* access type values [0-2] */
    int action_denied; /* is action denied values [0-1] */
    char date[20]; /* date */
    char time[10]; /* time */
    char file[100]; /* filename (string) */
    char fingerprint[100]; /* file fingerprint */
};

struct user_info {
    int uid;
    int modification_count;
    char fingerprints[MAX_MODIFICATIONS][MAX_FINGERPRINT_LENGTH];
};

void usage(void) {
    printf(
        "\n"
        "usage:\n"
        "\t./monitor \n"
        "Options:\n"
        "-m, Prints malicious users\n"
        "-i <filename>, Prints table of users that modified "
        "the file <filename> and the number of modifications\n"
        "-h, Help message\n\n"
    );
    exit(1);
}

void list_unauthorized_accesses(FILE *log) {
    struct log_entry entries[MAX_USERS];
    int malicious_users[MAX_USERS] = {0}; // Flag array for malicious users
    int access_counts[MAX_USERS] = {0}; // Count of unauthorized access attempts
    int user_count = 0;
    char hostname[MAX_HOSTNAME_LENGTH];

    if (gethostname(hostname, sizeof(hostname)) != 0) {
        perror("gethostname failed");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), log)) {
        // Parse date and time
        sscanf(line, "Date: %[^,], %[^\n]", entries[user_count].date, entries[user_count].time);

        // Parse UID
        fgets(line, sizeof(line), log);
        sscanf(line, "UID: %d", &entries[user_count].uid);

        // Parse file
        fgets(line, sizeof(line), log);
        sscanf(line, "File: %s", entries[user_count].file);

        // Parse access type
        fgets(line, sizeof(line), log);
        sscanf(line, "Access type: %d", &entries[user_count].access_type);

        // Parse action denied
        fgets(line, sizeof(line), log);
        sscanf(line, "Is action denied: %d", &entries[user_count].action_denied);

        // Parse fingerprint
        fgets(line, sizeof(line), log);
        sscanf(line, "Fingerprint: %s", entries[user_count].fingerprint);

        // Check if access was denied
        if (entries[user_count].action_denied == 1) {
            int uid = entries[user_count].uid;
            int found = 0;
            for (int i = 0; i < user_count; i++) {
                if (entries[i].uid == uid) {
                    access_counts[i]++;
                    found = 1;
                    break;
                }
            }
            if (!found && user_count < MAX_USERS) {
                entries[user_count].uid = uid;
                access_counts[user_count] = 1; // First unauthorized access
                user_count++;
            }
        }
    }

    // Print malicious users (more than 5 unauthorized access attempts)
    printf("Malicious Users:\n");
    for (int i = 0; i < user_count; i++) {
        if (access_counts[i] > 5) {
            printf("Hostname: %s\nUID: %d\nUnauthorized Access Attempts: %d\n",hostname, entries[i].uid, access_counts[i]);
        }
    }
}


void list_file_modifications(FILE *log, char *file_to_scan) {
    struct log_entry entry;
    struct user_info users[MAX_USERS] = {0};
    int tracked_user_count = 0;
    char hostname[MAX_HOSTNAME_LENGTH];

    if (gethostname(hostname, sizeof(hostname)) != 0) {
        perror("gethostname failed");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), log)) {
        // Parse date and time
        sscanf(line, "Date: %[^,], %[^\n]", entry.date, entry.time);

        // Parse UID
        fgets(line, sizeof(line), log);
        sscanf(line, "UID: %d", &entry.uid);

        // Parse file
        fgets(line, sizeof(line), log);
        sscanf(line, "File: %s", entry.file);

        // Parse access type
        fgets(line, sizeof(line), log);
        sscanf(line, "Access type: %d", &entry.access_type);

        // Parse action denied
        fgets(line, sizeof(line), log);
        sscanf(line, "Is action denied: %d", &entry.action_denied);

        // Parse fingerprint
        fgets(line, sizeof(line), log);
        sscanf(line, "Fingerprint: %s", entry.fingerprint);

        // Check if it is the desired file and if access is allowed
        if (strcmp(entry.file, file_to_scan) == 0 && entry.action_denied == 0) {
            int found = 0;

            // Search for the existence of the user
            for (int i = 0; i < tracked_user_count; i++) {
                if (users[i].uid == entry.uid) {
                    found = 1;

                    // Check if the fingerprint is already recorded
                    int is_new_fingerprint = 1;
                    for (int j = 0; j < users[i].modification_count; j++) {
                        if (strcmp(users[i].fingerprints[j], entry.fingerprint) == 0) {
                            is_new_fingerprint = 0;
                            break;
                        }
                    }

                    // If the fingerprint is new, store it and count it as a new modification
                    if (is_new_fingerprint) {
                        strcpy(users[i].fingerprints[users[i].modification_count], entry.fingerprint);
                        users[i].modification_count++;
                    }
                    break;
                }
            }

             // If the user is new, add them to the array and log the fingerprint
            if (!found && tracked_user_count < MAX_USERS) {
                users[tracked_user_count].uid = entry.uid;
                strcpy(users[tracked_user_count].fingerprints[0], entry.fingerprint);
                users[tracked_user_count].modification_count = 1;
                tracked_user_count++;
            }
        }
    }

    // Print the results
    printf("Modifications to %s:\n", file_to_scan);
    for (int i = 0; i < tracked_user_count; i++) {
        printf("Hostname: %s\nUID: %d\nModifications: %d\n",hostname, users[i].uid, users[i].modification_count);
    }
}

int main(int argc, char *argv[]) {
    int ch;
    FILE *log;

    if (argc < 2)
        usage();

    log = fopen("file_logging.log", "r");
    if (log == NULL) {
        printf("Error opening log file \"%s\"\n", "file_logging.log");
        return 1;
    }

    while ((ch = getopt(argc, argv, "hi:m")) != -1) {
        switch (ch) {
            case 'i':
                list_file_modifications(log, optarg);
                break;
            case 'm':
                list_unauthorized_accesses(log);
                break;
            default:
                usage();
        }
    }

    fclose(log);
    return 0;
}
