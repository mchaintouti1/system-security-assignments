#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>


void file_creation() {
    FILE *fd;
    const char *file_names[] = {
        "test_1.txt", 
        "test_2.txt", 
        "test_3.txt", 
        "test_4.txt", 
        "test_5.txt", 
        "test_6.txt", 
        "test_7.txt"
    };

    // Text content to write in each file
    const char *file_contents[] = {
        "This is test file 1.\n",
        "This is test file 2.\n",
        "This is test file 3.\n",
        "This is test file 4 \n", 
        "This is test file 5.\n",
        "This is test file 6.\n",
        "This is test file 7.\n"
    };

    printf("Creating test files...\n");
    for (int i = 0; i < 7; i++) {
        fd = fopen(file_names[i], "w");
        if (!fd) {
            printf("Failed to create %s\n", file_names[i]);
            continue;
        }
        if (i == 3) { // test_4.txt (write a random number)
            fprintf(fd, file_contents[i], rand());
        } else {
            fwrite(file_contents[i], 1, strlen(file_contents[i]), fd);
        }
        fclose(fd);
        printf("Created %s\n", file_names[i]); // Confirm that the file was created
    }
}

void denying_access() {
    const char *file_names[] = {
        "test_1.txt", 
        "test_2.txt", 
        "test_3.txt", 
        "test_4.txt", 
        "test_5.txt", 
        "test_6.txt", 
        "test_7.txt"
    };
    
    printf("Denying access to files...\n");
    for (int i = 0; i < 7; i++) {
        chmod(file_names[i], 0000); // No permissions
    }

    // Attempt to access files with denied permissions
    printf("Attempting to access denied files...\n");
    FILE *fd;
    for (int i = 0; i < 7; i++) {
        fd = fopen(file_names[i], "w");
        if (!fd) {
            printf("Access denied to %s\n", file_names[i]);
        } else {
            fclose(fd);
        }
    }
}

void permitting_access() {
    const char *file_names[] = {
        "test_1.txt", "test_2.txt", "test_3.txt", 
        "test_4.txt", "test_5.txt", "test_6.txt", "test_7.txt"
    };
    
    printf("Permitting access to files for everyone...\n");
    for (int i = 0; i < 7; i++) {
        chmod(file_names[i], S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH); // Δικαιώματα για όλους
    }

    // Attempt to access and write to files with permitted access
    printf("Attempting to access and write to permitted files...\n");
    FILE *fd;
    for (int i = 0; i < 7; i++) {
        fd = fopen(file_names[i], "w");
        if (fd) {
            // Write a message with the file number
            fprintf(fd, "Permission granted to file %d\n", i + 1);
            fclose(fd);
            printf("Wrote to %s: 'Permission granted to file %d'\n", file_names[i], i + 1);
        } else {
            printf("Failed to open %s for writing\n", file_names[i]);
        }
    }
}


int main() {

    file_creation();    // Create files
    denying_access();    // Deny access
    permitting_access(); // Permit access

    printf("Finished all operations.\n");
    return 0;
}
