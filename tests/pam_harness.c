#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Linux-PAM ABI, declared locally so PAM development headers are not needed. */
typedef struct pam_handle pam_handle_t;
struct pam_message {
    int msg_style;
    const char *msg;
};
struct pam_response {
    char *resp;
    int resp_retcode;
};
struct pam_conv {
    int (*conv)(int, const struct pam_message **, struct pam_response **, void *);
    void *appdata_ptr;
};
enum {
    PAM_SUCCESS = 0,
    PAM_PROMPT_ECHO_OFF = 1,
    PAM_PROMPT_ECHO_ON = 2,
    PAM_ERROR_MSG = 3,
    PAM_TEXT_INFO = 4,
    PAM_CONV_ERR = 19
};
struct credentials {
    const char *user;
    const char *password;
};

static void destroy_responses(struct pam_response *responses, int count) {
    if (!responses) return;
    for (int i = 0; i < count; ++i) {
        if (responses[i].resp) {
            explicit_bzero(responses[i].resp, strlen(responses[i].resp));
            free(responses[i].resp);
        }
    }
    free(responses);
}

static int converse(int count, const struct pam_message **messages,
                    struct pam_response **result, void *data) {
    if (!result) return PAM_CONV_ERR;
    *result = NULL;
    if (count <= 0 || count > 32 || !messages || !data) return PAM_CONV_ERR;
    const struct credentials *credentials = data;
    struct pam_response *responses = calloc((size_t)count, sizeof(*responses));
    if (!responses) return PAM_CONV_ERR;
    for (int i = 0; i < count; ++i) {
        if (!messages[i]) goto failure;
        const char *value = NULL;
        switch (messages[i]->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
            value = credentials->password;
            break;
        case PAM_PROMPT_ECHO_ON:
            value = credentials->user;
            break;
        case PAM_ERROR_MSG:
        case PAM_TEXT_INFO:
            /* Do not echo module messages, which might contain credentials. */
            break;
        default:
            goto failure;
        }
        if (value) {
            responses[i].resp = strdup(value);
            if (!responses[i].resp) goto failure;
        }
    }
    *result = responses;
    return PAM_SUCCESS;
failure:
    destroy_responses(responses, count);
    return PAM_CONV_ERR;
}

/* Usage: pam_harness CONFDIR SERVICE USER PASSWORD
 * Pass '-' for PASSWORD to read one line from stdin without exposing the secret
 * in the argument list. This harness deliberately performs authentication only;
 * account/session policy belongs to the SSH service configuration.
 */
int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s CONFDIR SERVICE USER PASSWORD (or - for stdin)\n", argv[0]);
        return 2;
    }
    char *password = NULL;
    size_t capacity = 0;
    if (strcmp(argv[4], "-") == 0) {
        ssize_t length = getline(&password, &capacity, stdin);
        if (length < 0) {
            if (password) explicit_bzero(password, capacity);
            free(password);
            fputs("Unable to read password\n", stderr);
            return 2;
        }
        if (length > 0 && password[length - 1] == '\n') password[--length] = '\0';
        if (length > 0 && password[length - 1] == '\r') password[--length] = '\0';
        if (memchr(password, '\0', (size_t)length)) {
            explicit_bzero(password, capacity);
            free(password);
            fputs("Password contains a NUL byte\n", stderr);
            return 2;
        }
    } else {
        capacity = strlen(argv[4]) + 1;
        password = strdup(argv[4]);
        explicit_bzero(argv[4], capacity - 1);
        if (!password) return 2;
    }

    int exit_status = 2;
    void *library = dlopen("libpam.so.0", RTLD_NOW | RTLD_GLOBAL);
    if (!library) {
        fputs("Unable to load libpam.so.0\n", stderr);
        goto cleanup;
    }
    int (*start)(const char *, const char *, const struct pam_conv *, const char *, pam_handle_t **);
    int (*authenticate)(pam_handle_t *, int);
    int (*end)(pam_handle_t *, int);
#define LOAD(target, name) do { \
    void *symbol = dlsym(library, name); \
    _Static_assert(sizeof(target) == sizeof(symbol), "Unsupported function pointer ABI"); \
    if (!symbol) { fputs("Missing PAM API: " name "\n", stderr); goto close_library; } \
    memcpy(&(target), &symbol, sizeof(target)); \
} while (0)
    LOAD(start, "pam_start_confdir");
    LOAD(authenticate, "pam_authenticate");
    LOAD(end, "pam_end");
#undef LOAD

    const struct credentials credentials = {argv[3], password};
    const struct pam_conv conversation = {converse, (void *)&credentials};
    pam_handle_t *handle = NULL;
    int status = start(argv[2], argv[3], &conversation, argv[1], &handle);
    if (status == PAM_SUCCESS) {
        status = authenticate(handle, 0);
        /* Only the numeric authentication result is emitted, never the secret. */
        printf("pam_authenticate=%d\n", status);
        exit_status = status;
    } else {
        fprintf(stderr, "pam_start_confdir=%d\n", status);
        exit_status = status;
    }
    if (handle) (void)end(handle, status);
close_library:
    dlclose(library);
cleanup:
    explicit_bzero(password, capacity);
    free(password);
    return exit_status;
}
