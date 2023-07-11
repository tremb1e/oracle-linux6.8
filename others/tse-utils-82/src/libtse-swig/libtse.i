%module libtse
%{
#include "../include/tse.h"
extern binary_data tse_passphrase_blob(char *salt, char *passphrase);
extern binary_data tse_passphrase_sig_from_blob(char *blob);
extern int tse_add_blob_to_keyring(char *blob, char *sig);
%}

#include "../include/tse.h"

%typemap(out) binary_data {
    $result = PyString_FromStringAndSize((char *)($1.data),$1.size);
}

extern binary_data tse_passphrase_blob(char *salt, char *passphrase);
extern binary_data tse_passphrase_sig_from_blob(char *blob);
extern int tse_add_blob_to_keyring(char *blob, char *sig);
