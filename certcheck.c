// COMP30023 Sem 1 2018 Assignment 2
// Nico Eka Dinata < n.dinata@student.unimelb.edu.au >
// @ndinata

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/safestack.h>

#define LINE_LENGTH 1024
#define VALID 1
#define INVALID 0
#define CN_SIZE 1024
#define BYTE_TO_BIT 8
#define MIN_KEY_LENGTH 2048

/* ---------------------- Helper function prototype ------------------------- */
int validate_cert(char* path_to_cert, char* url);
int validate_dates(X509* cert);
int validate_domain(X509* cert, char* url);
int validate_cn(X509* cert, char* url);
int validate_san(X509* cert, char* url);
int validate_name(char* buf, char* url);
int validate_key_length(X509* cert);
int validate_basic_constraints(X509* cert);
int validate_ext_key_usage(X509* cert);
char* get_extension_buf(X509* cert, int nid);


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

        // validate the cert and write the results into `output`
        int is_valid = validate_cert(path_to_cert, url);
        fprintf(output, "%s,%s,%d\n", path_to_cert, url, is_valid);
    }

    // close the input and output csv files
    fclose(output);
    fclose(fp);

    return EXIT_SUCCESS;
}


/* -------------------------------------------------------------------------- */
/**
 * Checks if the certificate located in `path_to_cert` is valid.
 * @param path_to_cert  path to the certificate
 * @param url           from which the certificate belongs
 * @return whether the cert is valid (1) or not (0)
 */
int validate_cert(char* path_to_cert, char* url) {
    BIO* certificate_bio = NULL;
    X509* cert = NULL;

    // initialise OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    // create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    // read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, path_to_cert))) {
        fprintf(stderr, "Error in reading cert BIO filename\n");
        exit(EXIT_FAILURE);
    }
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL))) {
        fprintf(stderr, "Error in loading certificate\n");
        exit(EXIT_FAILURE);
    }

    /* cert contains the X509 certificate and is ready to be validated */

    // first, check the dates
    if (!validate_dates(cert)) {
        return INVALID;
    }

    // validate domain name
    if (!validate_domain(cert, url)) {
        return INVALID;
    }

    // validate key length
    if (!validate_key_length(cert)) {
        return INVALID;
    }

    // validate BasicConstraints
    if (!validate_basic_constraints(cert)) {
        return INVALID;
    }

    // validate Extended Key Usage
    if (!validate_ext_key_usage(cert)) {
        return INVALID;
    }

    // no longer need cert, free it
    X509_free(cert);
    BIO_free_all(certificate_bio);

    // cert passes all those validation checks; it's valid!
    return VALID;
}


/**
 * Checks the `notBefore` and `notAfter` dates of the cert.
 * @param cert  whose dates are to be validated
 * @return whether the dates are valid (1) or not (0)
 */
int validate_dates(X509* cert) {
    int day, sec;

    // check the `notBefore` date
    ASN1_TIME* before = X509_get_notBefore(cert);
    if (!ASN1_TIME_diff(&day, &sec, NULL, before)) {
        fprintf(stderr, "Error checking `Not Before` date\n");
        exit(EXIT_FAILURE);
    }

    // if `day` or `sec` is +ve, `notBefore` is in the future; hence, invalid cert
    if (day > 0 || sec > 0) {
        return INVALID;
    }

    // check the `notAfter` (expiry) date
    ASN1_TIME* after = X509_get_notAfter(cert);
    if (!ASN1_TIME_diff(&day, &sec, NULL, after)) {
        fprintf(stderr, "Error checking `Not After` date\n");
        exit(EXIT_FAILURE);
    }

    // if `day` or `sec` is negative, `notAfter` is in the past (expired)
    if (day < 0 || sec < 0) {
        return INVALID;
    }

    // dates are valid!
    return VALID;
}


/**
 * Checks the domain name of the cert.
 * @param cert  whose name is to be validated
 * @param url   to which the cert is supposed to belong
 * @return whether the domain name is valid (1) or not (0)
 */
int validate_domain(X509* cert, char* url) {
    // check whether CommonName (CN) corresponds to URL
    int cn_valid = validate_cn(cert, url);

    // check whether any of the Subject Alternative Names (SAN) corresponds to URL
    int san_valid = validate_san(cert, url);

    return (cn_valid || san_valid);
}


/**
 * Checks whether the cert's CommonName matches its URL.
 * @param cert  whose CommonName is to be checked
 * @param url   to which the cert's CommonName is compared
 * @return whether the cert's CommonName matches the URL (1) or not (0)
 */
int validate_cn(X509* cert, char* url) {
    char* cn = (char*)malloc(CN_SIZE * sizeof(char));
    assert(cn);

    // obtain the cert's CN
    X509_NAME* common_name = X509_get_subject_name(cert);
    if (X509_NAME_get_text_by_NID(common_name, NID_commonName, cn, CN_SIZE) < 0) {
        fprintf(stderr, "CN not found\n");
        exit(EXIT_FAILURE);
    }

    // check whether the cert's CN matches outright or through wildcards
    int is_valid = validate_name(cn, url);
    free(cn);
    return is_valid;
}


/**
 * Checks whether any of the cert's Subject Alternative Names (SAN) corresponds
 * to its URL.
 * @param cert  whose SAN is to be checked
 * @param url   to which the cert's SAN is compared
 * @return whether they match (1) or not (0)
 */
int validate_san(X509* cert, char* url) {
    // obtain the buffer containing the SAN's, if it exists
    char* buf = get_extension_buf(cert, NID_subject_alt_name);
    if (buf == NULL) {
        return INVALID;
    }

    // parse the buffer and extract the individual SAN's
    char* end_entry;
    char* full_san = strtok_r(buf, ",", &end_entry);

    // exhaust the SAN's until we find one that matches
    while (full_san != NULL) {
        char* end_san;
        char* dns = strtok_r(full_san, ":", &end_san);      // 'DNS' (unused)
        char* san = strtok_r(NULL, ":", &end_san);          // the actual SAN value

        // check whether the SAN matches outright or through wildcards
        if (validate_name(san, url)) {
            free(buf);
            return VALID;
        }

        full_san = strtok_r(NULL, ",", &end_entry);
    }

    free(buf);      // buf is dynamically allocated in get_extension_buf(...)

    // went through all of the SAN's; no match
    return INVALID;
}


/**
 * Checks whether `name` matches `URL`, outright or through wildcards.
 * @param name  of the cert (CommonName or Subject Alternative Name)
 * @param url   to which the name will be compared
 * @return whether `name` and `url` match (1) or not (0)
 */
int validate_name(char* name, char* url) {
    int is_valid = 0;

    // check if name matches URL outright
    if (!strncmp(url, name, strlen(url))) {
        return VALID;
    }

    /* ok, how about through wildcards? */

    // duplicate `url` because we're potentially manipulating it with strtok_r()
    char* url_temp = strndup(url, strlen(url));

    if (name[0] == '*') {
        // setup the name (CN or SAN)
        char* name_end;
        char* asterisk = strtok_r(name, ".", &name_end);
        char* name_label = strtok_r(NULL, ".", &name_end);

        // setup the URL (domain)
        char* url_end;
        char* url_left = strtok_r(url_temp, ".", &url_end); // left-most URL label
        char* url_label = strtok_r(NULL, ".", &url_end);

        // the immediate label after the asterisk should match the URL's
        // second label from the left (asterisk covers the first label); then,
        // the subsequent labels have to match
        while (name_label && url_label) {
            if (!strncmp(name_label, url_label, strlen(name_label))) {
                name_label = strtok_r(NULL, ".", &name_end);
                url_label  = strtok_r(NULL, ".", &url_end);
                is_valid = VALID;
            } else {
                is_valid = INVALID;
                break;
            }
        }
    }

    free(url_temp);
    return is_valid;
}


/**
 * Checks whether the cert's minimum RSA key length is 2048 bits.
 * @param cert  whose key length is to be validated
 * @return whether key length is at least 2048 bits (1) or not (0)
 */
int validate_key_length(X509* cert) {
    // obtain the key from the cert
    EVP_PKEY* public_key = X509_get_pubkey(cert);
    if (public_key == NULL) {
        fprintf(stderr, "Error getting public key\n");
        exit(EXIT_FAILURE);
    }

    // assume all certificates will use RSA keys, as per the spec
    RSA* rsa_key = EVP_PKEY_get1_RSA(public_key);

    // get the size of the key, although in bytes
    int key_length = RSA_size(rsa_key);

    // need to be freed, as per the documentation
    RSA_free(rsa_key);
    EVP_PKEY_free(public_key);

    // check if key length (in bits) is at least 2048 bits
    if ((key_length * BYTE_TO_BIT) >= MIN_KEY_LENGTH) {
        return VALID;
    }

    return INVALID;
}


/**
 * Checks whether the cert can act as a CA or not, based on its BasicConstraints.
 * @param cert  whose BasicConstraints is to be validated
 * @return whether the cert can act as a CA (0) or not (1)
 */
int validate_basic_constraints(X509* cert) {
    // obtain the cert's BasicConstraints
    BASIC_CONSTRAINTS* bs;
    bs = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL);

    int is_valid = 0;
    if (bs != NULL) {
        // bs->ca is 1 if CA:TRUE and vice versa, so we want its oppposite,
        // since we only consider the cert to be valid if CA:FALSE
        is_valid = !bs->ca;
        BASIC_CONSTRAINTS_free(bs);
    } else {
        // if BasicConstraints is missing in the cert, it is assumed to not be a CA
        is_valid = VALID;
    }

    return is_valid;
}


/**
 * Checks whether one of the cert's usages is for TLS Web Server Authentication.
 * @param cert  whose Extended Key Usage(s) is to be validated
 * @return whether the cert is for serverAuth (1) or not (0)
 */
int validate_ext_key_usage(X509* cert) {
    // obtain the cert's Extended Key Usage(s)
    EXTENDED_KEY_USAGE* ext_key_usages;
    ext_key_usages = X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);

    int is_valid = 0;
    if (ext_key_usages != NULL) {
        int i;
        // iterate over all of the usage(s)
        for (i = 0; i < sk_ASN1_OBJECT_num(ext_key_usages); i++) {
            int nid = OBJ_obj2nid(sk_ASN1_OBJECT_value(ext_key_usages, i));

            // only valid if the usage is for TLS Web Server Authentication
            if (nid == NID_server_auth) {
                is_valid = VALID;
                break;
            }
        }
        EXTENDED_KEY_USAGE_free(ext_key_usages);
    }

    return is_valid;
}


/**
 * Retrieves a string buffer containing the extension's value(s). The buffer
 * returned needs to be freed.
 * @param cert  whose extension is to be validated
 * @param nid   of the extension whose value(s) are being extracted
 * @return buffer containing the extension's value(s)
 */
char* get_extension_buf(X509* cert, int nid) {
    // check whether the cert actually has the extension
    int loc = X509_get_ext_by_NID(cert, nid, -1);
    if (loc == -1) {
        return NULL;
    }

    // the extension is present; obtain its value(s)
    X509_EXTENSION* ex = X509_get_ext(cert, loc);
    BUF_MEM* bptr = NULL;
    char* buf = NULL;
    BIO* bio = BIO_new(BIO_s_mem());

    if (!X509V3_EXT_print(bio, ex, 0, 0)) {
        fprintf(stderr, "Error in reading extensions\n");
    }

    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    // bptr->data is not NULL terminated - add null character
    buf = (char *)malloc((bptr->length + 1) * sizeof(char));
    assert(buf);
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';

    BIO_free_all(bio);

    return buf;
}