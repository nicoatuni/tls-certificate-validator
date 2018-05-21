#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

/* DEBUGGING -- REMOVE ------------------------------------------------- */
#ifdef DEBUG
#define DLOG(...) printf(__VA_ARGS__)
#else
#define DLOG(...) do {} while(0)
#endif
/* --------------------------------------------------------------------- */

# define LINE_LENGTH 1024
# define VALID 1
# define INVALID 0
# define CN_BUF_SIZE 1024
# define BYTE_TO_BIT 8
# define MIN_KEY_LENGTH 2048

/* ---------------------- Helper function prototype ------------------------- */
void validate_cert(FILE* output, char* path_to_cert, char* url);

/* DEBUGGING -- REMOVE & UNCOMMENT BELOW ------------------------------- */
int validate_dates(X509 *cert, char* path_to_cert);
int validate_san(int cn_valid, X509* cert, char* url);
/* --------------------------------------------------------------------- */
// int validate_dates(X509 *cert);
// int validate_san(X509* cert, char* url);
int validate_domain(X509 *cert, char* url);
int validate_cn(X509 *cert, char* url);
int validate_name(char* buf, char* url);
int validate_key_length(X509 *cert);
int validate_basic_constraints(X509* cert);
int validate_ext_key_usage(X509* cert);

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

    /* DEBUGGING -- REMOVE --------------------------------------------- */
    DLOG("=========================================\n");
    /* ----------------------------------------------------------------- */

    // read the contents of the input csv file
    char line[LINE_LENGTH];
    while (fgets(line, LINE_LENGTH, fp)) {
        char* path_to_cert = strtok(line, ",");
        char* url = strtok(NULL, ",\n");

        // handle certificate validation
        validate_cert(output, path_to_cert, url);
    }

    /* DEBUGGING -- REMOVE --------------------------------------------- */
    DLOG("=========================================\n");
    /* ----------------------------------------------------------------- */

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
    // STACK_OF(X509_EXTENSION) * ext_list;

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
    // first, check the dates
    /* DEBUGGING -- REMOVE & UNCOMMENT BELOW --------------------------- */
    if (!validate_dates(cert, path_to_cert)) {
    /* ----------------------------------------------------------------- */
    // if (!validate_dates(cert)) {
        fprintf(output, "%s,%s,%d\n", path_to_cert, url, INVALID);
        return;
    }

    // validate domain name
    if (!validate_domain(cert, url)) {
        fprintf(output, "%s,%s,%d\n", path_to_cert, url, INVALID);
        return;
    }

    // validate key length
    if (!validate_key_length(cert)) {
        fprintf(output, "%s,%s,%d\n", path_to_cert, url, INVALID);
        return;
    }

    // validate BasicConstraints
    if (!validate_basic_constraints(cert)) {
        fprintf(output, "%s,%s,%d\n", path_to_cert, url, INVALID);
        return;
    }

    // validate Extended Key Usage
    if (!validate_ext_key_usage(cert)) {
        fprintf(output, "%s,%s,%d\n", path_to_cert, url, INVALID);
        return;
    }
    
    // the minimum checking you are expected to do is as follows:
    // 1. [X] validation of dates, both the `Not Before` and `Not After` dates
    // 2. [X] domain name validation, including SAN extension, and wildcards
    // 3. [X] minimum key length of 2048 bits for RSA
    // 4. [ ] correct key usage, including extensions

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
    fprintf(output, "%s,%s,%d\n", path_to_cert, url, VALID);

    X509_free(cert);
    BIO_free_all(certificate_bio);
}


/**
 * Checks the `notBefore` and `notAfter` dates of the cert.
 * @param cert  whose dates are to be validated
 * @return whether the dates are valid (1) or not (0)
 */
/* DEBUGGING -- REMOVE & UNCOMMENT BELOW ------------------------------- */
int validate_dates(X509 *cert, char* path_to_cert) {
/* --------------------------------------------------------------------- */
// int validate_dates(X509 *cert) {
    int day, sec;

    // check the `notBefore` date
    ASN1_TIME *before = X509_get_notBefore(cert);
    if (!ASN1_TIME_diff(&day, &sec, NULL, before)) {
        perror("Error checking `Not Before` date");
        exit(EXIT_FAILURE);
    }

    // if `day` or `sec` is positive, `notBefore` is in the future
    // hence, invalid cert
    if (day > 0 || sec > 0) {
        /* DEBUGGING -- REMOVE ----------------------------------------- */
        DLOG("%-15s: `notBefore` is in the future (X)\n", path_to_cert);
        /* ------------------------------------------------------------- */
        return INVALID;
    }

    // check the `notAfter` (expiry) date
    ASN1_TIME *after = X509_get_notAfter(cert);
    if (!ASN1_TIME_diff(&day, &sec, NULL, after)) {
        perror("Error checking `Not After` date");
        exit(EXIT_FAILURE);
    }

    // if `day` or `sec` is negative, `notAfter` is in the past
    if (day < 0 || sec < 0) {
        /* DEBUGGING -- REMOVE ----------------------------------------- */
        DLOG("%-15s: `notAfter` is in the past (X)\n", path_to_cert);
        /* ------------------------------------------------------------- */
        return INVALID;
    }

    // dates are valid!
    /* DEBUGGING -- REMOVE ----------------------------------------- */
    DLOG("%-15s: Dates are valid (OK), ", path_to_cert);
    /* ------------------------------------------------------------- */
    return VALID;
}


/**
 * Checks the domain name of the cert.
 * @param cert  whose name is to be validated
 * @param url   to which the cert is supposed to belong to
 * @return whether the name is valid (1) or not (0)
 */
int validate_domain(X509 *cert, char* url) {
    // check whether CommonName (CN) corresponds to URL
    int cn_valid = validate_cn(cert, url);

    // check whether any of the Subject Alternative Names (SAN) corresponds to URL
    int san_valid = validate_san(cn_valid, cert, url);

    return (cn_valid || san_valid);
}


/**
 * Checks whether the cert's CommonName corresponds to its URL.
 * @param cert  whose CommonName is to be checked
 * @param url   to which the cert's CommonName is compared
 * @return whether the cert's CommonName corresponds to the URL (1) or not (0)
 */
int validate_cn(X509 *cert, char* url) {
    // obtain the cert's CN
    char* cn_buf = (char*)malloc(CN_BUF_SIZE * sizeof(char));
    X509_NAME *common_name = X509_get_subject_name(cert);
    if (X509_NAME_get_text_by_NID(common_name, NID_commonName, cn_buf, CN_BUF_SIZE) < 0) {
        fprintf(stderr, "CN NOT FOUND\n");
        exit(EXIT_FAILURE);
    }

    /* DEBUGGING -- REMOVE --------------------------------------------- */
    DLOG("CN: ");
    /* ----------------------------------------------------------------- */

    int is_valid = validate_name(cn_buf, url);
    free(cn_buf);
    return is_valid;
}


/**
 * Checks whether any of the cert's Subject Alternative Names corresponds to its
 * URL.
 * @param cn_valid  whether the cert's CommonName corresponds to its URL
 * @param cert      whose Subject Alternative Name is to be checked
 * @param url       to which the cert's Subject Alternative Name is compared
 * @return whether they correspond (1) or not (0)
 */
/* DEBUGGING -- REMOVE & UNCOMMENT BELOW ------------------------------- */
int validate_san(int cn_valid, X509* cert, char* url) {
/* --------------------------------------------------------------------- */
// int validate_san(X509* cert, char* url) {
    int loc = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    if (loc == -1) {
        /* DEBUGGING -- REMOVE ----------------------------------------- */
        if (!cn_valid) {
            DLOG("CN does not match URL + No SAN (X)\n");
        }
        /* ------------------------------------------------------------- */
        return INVALID;
    }

    /* DEBUGGING -- REMOVE --------------------------------------------- */
    if (cn_valid) {
        DLOG("CN matches URL + SAN (OK), ");
    } else {
        DLOG("CN does not match URL + SAN (?), ");
    }
    /* ----------------------------------------------------------------- */

    // SAN(s) are present; obtain their value(s)
    X509_EXTENSION *ex = X509_get_ext(cert, loc);
    BUF_MEM *bptr = NULL;
    char *buf = NULL;
    BIO *bio = BIO_new(BIO_s_mem());

    if (!X509V3_EXT_print(bio, ex, 0, 0)) {
        fprintf(stderr, "Error in reading extensions\n");
    }

    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    // bptr->data is not NULL terminated - add null character
    buf = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';

    // get the first SAN
    char* end_entry;
    char* entry = strtok_r(buf, ",", &end_entry);

    while (entry != NULL) {
        char* end_san;
        char* flush = strtok_r(entry, ":", &end_san);
        char* san   = strtok_r(NULL, ":", &end_san);

        /* DEBUGGING -- REMOVE ----------------------------------------- */
        DLOG("SAN: ");
        /* ------------------------------------------------------------- */
        if (validate_name(san, url)) {
            return VALID;
        }

        entry = strtok_r(NULL, ",", &end_entry);
    }

    BIO_free_all(bio);
    free(buf);

    return INVALID;
}


/**
 * Checks whether any of the cert's name (can be CommonName or Subject Alternative
 * Name) correspond to the cert's URL.
 * @param name  of the cert (CommonName or Subject Alternative Name)
 * @param url   to which the name will be compared
 * @return whether `name` and `url` correspond
 */
int validate_name(char* name, char* url) {
    // check if name matches URL outright
    if (!strncmp(url, name, strlen(url))) {
        /* DEBUGGING -- REMOVE ----------------------------------------- */
        DLOG("Name matches URL (OK), ");
        /* ------------------------------------------------------------- */

        return VALID;
    } else {
        // maybe it matches through a wildcard?
        if (name[0] == '*') {
            char* name_temp = name + 1;
            char* wildcard;

            wildcard = strstr(url, name_temp);
            if (wildcard != NULL) {
                /* DEBUGGING -- REMOVE --------------------------------- */
                DLOG("Wilcard matches URL (OK), ");
                /* ----------------------------------------------------- */

                // it _does_ match!
                return VALID;
            }
        }
    }

    return INVALID;
}


/**
 * Checks whether the cert's minimum RSA key length is 2048 bits.
 * @param cert  whose key length is to be validated
 * @return whether key length is at least 2048 bits (1) or not (0)
 */
int validate_key_length(X509 *cert) {
    // obtain the key from the cert
    EVP_PKEY* public_key = X509_get_pubkey(cert);

    // assume all certificates will use RSA keys, as per the spec
    RSA* rsa_key = EVP_PKEY_get1_RSA(public_key);

    // get the size of the key, although in bytes
    int key_length = RSA_size(rsa_key);

    // need to be freed, as per the documentation
    RSA_free(rsa_key);
    EVP_PKEY_free(public_key);

    // check if key length (in bits) is at least 2048 bits
    if ((key_length * BYTE_TO_BIT) >= MIN_KEY_LENGTH) {
        /* DEBUGGING -- REMOVE ----------------------------------------- */
        DLOG("Key length >= 2048 bits (OK), ");
        /* ------------------------------------------------------------- */

        return VALID;
    }
    /* DEBUGGING -- REMOVE --------------------------------------------- */
    DLOG("Key length < 2048 bits (X)\n");
    /* ----------------------------------------------------------------- */
    return INVALID;
}


/**
 * 
 * @param cert  whose BasicConstraints is to be validated
 * @return whether the cert can act as a CA (0) or not (1)
 */
int validate_basic_constraints(X509* cert) {
    int loc = X509_get_ext_by_NID(cert, NID_basic_constraints, -1);
    if (loc == -1) {
        /* DEBUGGING -- REMOVE ----------------------------------------- */
        DLOG("%-15s  %-30s (0)\n", "", "Basic Constraints extension not present");
        /* ------------------------------------------------------------- */
        return INVALID;
    }

    // BasicConstraints extension is present; obtain its value
    X509_EXTENSION *ex = X509_get_ext(cert, loc);
    BUF_MEM *bptr = NULL;
    char *buf = NULL;
    BIO *bio = BIO_new(BIO_s_mem());

    if (!X509V3_EXT_print(bio, ex, 0, 0)) {
        fprintf(stderr, "Error in reading extensions\n");
    }

    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    // bptr->data is not NULL terminated - add null character
    buf = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';

    char* end_entry;
    char* entry = strtok_r(buf, ",", &end_entry);

    while (entry != NULL) {
        char* end_is_ca;
        char* flush = strtok_r(entry, ":", &end_is_ca);
        if (strncmp(flush, "CA", strlen("CA"))) {
            entry = strtok_r(NULL, ",", &end_entry);
            continue;
        }

        char* is_ca = strtok_r(NULL, ":", &end_is_ca);

        if (!strncmp(is_ca, "FALSE", strlen("FALSE"))) {
            /* DEBUGGING -- REMOVE ----------------------------------------- */
            DLOG("CA: False (OK), ");
            /* ------------------------------------------------------------- */
            return VALID;
        }

        entry = strtok_r(NULL, ",", &end_entry);
    }

    /* DEBUGGING -- REMOVE ----------------------------------------- */
    DLOG("CA: True (X)\n");
    /* ------------------------------------------------------------- */
    return INVALID;
}


/**
 * 
 */
int validate_ext_key_usage(X509* cert) {
    int loc = X509_get_ext_by_NID(cert, NID_ext_key_usage, -1);
    if (loc == -1) {
        /* DEBUGGING -- REMOVE ----------------------------------------- */
        DLOG("%-15s  %-30s (0)\n", "", "Extended Key Usage extension not present");
        /* ------------------------------------------------------------- */
        return INVALID;
    }

    // Extended Key Usage extension is present; obtain its value
    X509_EXTENSION *ex = X509_get_ext(cert, loc);
    BUF_MEM *bptr = NULL;
    char *buf = NULL;
    BIO *bio = BIO_new(BIO_s_mem());

    if (!X509V3_EXT_print(bio, ex, 0, 0)) {
        fprintf(stderr, "Error in reading extensions\n");
    }

    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    // bptr->data is not NULL terminated - add null character
    buf = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';

    char* usage = strtok(buf, ",");

    while (usage != NULL) {
        if (!strncmp(usage, LN_server_auth, strlen(LN_server_auth))) {
            /* DEBUGGING -- REMOVE ----------------------------------------- */
            DLOG("Server Auth (OK)\n");
            /* ------------------------------------------------------------- */
            return VALID;
        }

        usage = strtok(NULL, ",");
    }

    /* DEBUGGING -- REMOVE ----------------------------------------- */
    DLOG("Non-Server Auth (X)\n");
    /* ------------------------------------------------------------- */
    return INVALID;
}