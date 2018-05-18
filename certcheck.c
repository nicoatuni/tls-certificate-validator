#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <openssl/x509.h>
// #include <openssl/x509v3.h>
// #include <openssl/bio.h>
// #include <openssl/pem.h>
// #include <openssl/err.h>

# define LINE_LENGTH 1024

int main(int argc, char const *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s path_to_csv_file\n", argv[0]);
        return EXIT_FAILURE;
    }

    // open the input csv file
    const char* csv_filename = argv[1];
    FILE* fp = fopen(csv_filename, "r");
    if (fp == NULL) {
        perror("Error opening input csv file");
        return EXIT_FAILURE;
    }

    // open the output file
    FILE* output = fopen("output.csv", "a");
    if (output == NULL) {
        perror("Error opening output file");
        return EXIT_FAILURE;
    }

    // read the contents of the input csv file
    char line[LINE_LENGTH];
    while (fgets(line, LINE_LENGTH, fp)) {
        char* path_to_cert = strtok(line, ",");
        char* url = strtok(NULL, ",\n");

        // write content into output file
        fprintf(output, "%s and %s\n", path_to_cert, url);
    }

    
    // close the input and output csv files
    fclose(output);
    fclose(fp);

    return EXIT_SUCCESS;
}