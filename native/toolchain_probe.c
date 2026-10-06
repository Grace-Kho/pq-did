#include <oqs/oqs.h>
#include <string.h>

int pqdid_check_native_backend(void) {
    OQS_init();
    OQS_SIG *signature = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (signature == NULL) {
        OQS_destroy();
        return 1;
    }
    const int valid = strcmp(OQS_version(), "0.16.0") == 0
        && signature->length_public_key == 1952
        && signature->length_secret_key == 4032
        && signature->length_signature == 3309
        && signature->sig_with_ctx_support;
    OQS_SIG_free(signature);
    OQS_destroy();
    return valid ? 0 : 1;
}
