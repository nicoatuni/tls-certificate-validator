#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/asn1.h>

# define LINE_LENGTH 1024

/* ---------------------- Helper function prototype ------------------------- */
void validate_cert(FILE* output, char* path_to_cert, char* url);


/* ----------------------------- Main Program ------------------------------- */
int main(int argc, char const *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s path_to_csv_file\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // open the input csv file
    const char* csv_filename = argv[1];
    FILE* fp = fopen(csv_filename, "r");
    if (fp == NULL) {
        perror("Error opening input csv file");
        exit(EXIT_FAILURE);
    }

    // open the output file
    FILE* output = fopen("output.csv", "a");
    if (output == NULL) {
        perror("Error opening output file");
        exit(EXIT_FAILURE);
    }

    // read the contents of the input csv file
    char line[LINE_LENGTH];
    while (fgets(line, LINE_LENGTH, fp)) {
        char* path_to_cert = strtok(line, ",");
        char* url = strtok(NULL, ",\n");

        /* DEBUGGING -- TO BE REMOVED --------------------------------- */
        // fprintf(output, "%s and %s\n", path_to_cert, url);
        /* ------------------------------------------------------------ */

        // handle certificate validation
        validate_cert(output, path_to_cert, url);
    }
    
    // close the input and output csv files
    fclose(output);
    fclose(fp);

    return EXIT_SUCCESS;
}


/* -------------------------------------------------------------------------- */
/**
 * Checks if the certificate located in `path_to_cert` is valid and writes the
 * output to `output`.
 * @param output file
 * @param path_to_cert path to the certificate
 * @param url from which the certificate belongs
 */
void validate_cert(FILE* output, char* path_to_cert, char* url) {
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;
    X509_NAME *cert_issuer = NULL;
    STACK_OF(X509_EXTENSION) * ext_list;

    // initialise OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    // create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    // read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, path_to_cert))) {
        fprintf(stderr, "Error in reading cert BIO filename");
        exit(EXIT_FAILURE);
    }

    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL))) {
        fprintf(stderr, "Error in loading certificate");
        exit(EXIT_FAILURE);
    }

    // cert contains the x509 certificate and is ready to be validated!
    int is_valid = 0;

    // check the `Not Before` date
    int day, sec;
    ASN1_TIME *before = X509_get_notBefore(cert);
    if (!ASN1_TIME_diff(&day, &sec, NULL, before)) {
        perror("Error checking `Not Before` date");
        exit(EXIT_FAILURE);
    }

    // valid only if `before` is actually before current time
    if (day <= 0 || sec <= 0) {
        is_valid = 1;
    }

    
    // the minimum checking you are expected to do is as follows:
    // 1. validation of dates, both the `Not Before` and `Not After` dates
    // 2. domain name validation, including Subject Alternative Name (SAN) extension, and wildcards
    // 3. minimum key length of 2048 bits for RSA
    // 4. correct key usage, including extensions

    // You  can  assume  that  there  are  no  restrictions  on  Subject  Alternative Name’s  beyond  the  specification,  and  in  particular  that  wildcard  domains are allowed in both the Common Name and the SAN.
    // Your checking code should handle such wildcards correctly. You can assume that all certificates will use RSA keys.

    // Part B Basic Certificate Checking (5 marks)
    // – Reads input CSV and write output CSV (1 mark)
    // – Correctly validates `Not Before` date (1 mark)
    // – Correctly validates `Not After` date (1 mark)
    // – Correctly validates domain name in Common Name (2 mark)

    // Part C Advanced Certificate Checking (5 marks)
    // – Correctly validates minimum RSA key length of 2048 bits (1 mark)
    // – Correctly validates key usage and constraints (2 mark)
    //      ∗ BasicConstraints includes “CA:FALSE”
    //      ∗ Enhanced Key Usage includes “TLS Web Server Authentication”
    // – Correctly validates Subject Alternative Name extension (2 marks)

    // A list of function calls you may NOT use is as follows:
    // - X509_check_ca
    // - X509_check_host
    // - X509_cmp_current_time
    // - X509_cmp_time

    // write output into the output file
    fprintf(output, "%s,%s,%d\n", path_to_cert, url, is_valid);
}