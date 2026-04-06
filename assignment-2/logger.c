#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dlfcn.h>
#include <assert.h>
#include <openssl/evp.h>

// SHA-256 hash computation
void sha256_hash(const unsigned char *message, size_t message_len, unsigned char *hash) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_get_digestbyname("SHA256");
    unsigned int hash_len;

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, message, message_len);
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);

    EVP_MD_CTX_free(mdctx);
}

// Logging function
void write_log(const char *file_name, int access_type, int is_action_denied, unsigned char *file_content, size_t content_len) {
    // Get user ID and current time
    uid_t user_id = getuid();
    time_t curr_time = time(NULL);
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    assert(gmtime_r(&curr_time, &tm) != NULL);

    // Compute fingerprint
    unsigned char md_value[EVP_MAX_MD_SIZE] = {0};
    if (content_len > 0) {
        sha256_hash(file_content, content_len, md_value);
    }

    // Write to log
    FILE *log_file = fopen("file_logging.log", "a");
    if (log_file != NULL) {
        fprintf(log_file, "Date: %04d-%02d-%02d, %02d:%02d:%02d\n", 
                1900 + tm.tm_year, tm.tm_mon + 1, tm.tm_mday, 
                tm.tm_hour, tm.tm_min, tm.tm_sec);
        fprintf(log_file, "UID: %d\nFile: %s\n", user_id, file_name);
        fprintf(log_file, "Access type: %d\nIs action denied: %d\nFingerprint: ", 
                access_type, is_action_denied);

        // Display the fingerprint
        if (content_len > 0) {
            for (size_t i = 0; i < EVP_MD_size(EVP_get_digestbyname("SHA256")); i++) {
                fprintf(log_file, "%02x", md_value[i]);
            }
			fprintf(log_file, "\n");
        } else {
            fprintf(log_file, "NULL\n"); // Αν δεν υπάρχει περιεχόμενο, καταγραφή ως NULL
        }

        fprintf(log_file, "\n");
        fclose(log_file);
    }
}

// Interception of fopen
FILE *fopen(const char *path, const char *mode) {
    FILE *original_fopen_ret;
    FILE *(*original_fopen)(const char *, const char *);
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    original_fopen_ret = (*original_fopen)(path, mode);

    // Avoid logging when opening the log file
    if (strcmp(path, "file_logging.log") == 0) // We don't log this file 
        return original_fopen_ret;

    int access_type = 0;
    int is_access_denied = 0;
    unsigned char file_content[4096];  // Buffer for file content
    size_t content_len = 0;

    // Access checks
    if (access(path, F_OK) != -1) {
        access_type = 1; // File open
        if (strchr(mode, 'r') != NULL) {
            if (access(path, R_OK) == 0) {
                is_access_denied = 0;
				
            } else {
                is_access_denied = 1; // Deny access
            }
        } else if (strchr(mode, 'w') != NULL || strchr(mode, 'a') != NULL) {
            if (access(path, W_OK) == 0) {
                //access_type = 2; // File writing
                is_access_denied = 0;

                // Logging without reading content
                content_len = sizeof(file_content); // Optionally change content if needed
                memcpy(file_content, "Sample Data", content_len);// Add content to be logged
            } else {
                //access_type = 2; // File writing
                is_access_denied = 1; // Deny access
            }
        }
    } else {
        access_type = 0; // File creation
        //is_access_denied = 0; // No denial for creation
    }

    // Write to log
    write_log(strrchr(path, '/') ? strrchr(path, '/') + 1 : path, access_type, is_access_denied, file_content, content_len);

    return original_fopen_ret;
}

// Interception of fwrite
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t original_fwrite_ret;
    size_t (*original_fwrite)(const void *, size_t, size_t, FILE *);
    original_fwrite = dlsym(RTLD_NEXT, "fwrite");
    original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

    // Check file descriptor and path
    int fd = fileno(stream);
    char path[1024] = {0};
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    char actual_path[1024] = {0};
    ssize_t len = readlink(path, actual_path, sizeof(actual_path) - 1);
    if (len == -1) {
        perror("Failed to retrieve file path.");
        return 0;
    }
    actual_path[len] = '\0';

    // Variable setup
    int access_type = -1;
    int is_access_denied = 1;
    unsigned char file_content[4096]; // Buffer for file content
    size_t content_len = size * nmemb; // Bytes to write

    // Check write permissions
    if (access(actual_path, W_OK) == 0) {
        access_type = 2; // Write access
        is_access_denied = 0;

        // Copy the content
        memcpy(file_content, ptr, content_len); // Copy the content
    } else {
        access_type = 2; // Write access
        is_access_denied = 1; // Deny access
    }

    // Write to log
    write_log(strrchr(actual_path, '/') ? strrchr(actual_path, '/') + 1 : actual_path, access_type, is_access_denied, file_content, content_len);

    return original_fwrite_ret;
}
