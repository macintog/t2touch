// SPDX-License-Identifier: GPL-2.0-only
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdlib.h>
#include <string.h>

static const char data_key[] = "t2touch-action-prompt";
static const char action_prompt[] =
    "Place your finger on the fingerprint reader";
static const char marked_action_prompt[] =
    "◎ Place your finger on the fingerprint reader";

struct prompt_context {
    struct pam_conv upstream;
    struct pam_conv replacement;
};

static int marked_conversation(int count, const struct pam_message **messages,
                               struct pam_response **responses, void *data)
{
    struct prompt_context *context = data;
    struct pam_message *rewritten;
    const struct pam_message **forwarded;
    int result;
    int index;

    if (count <= 0 || messages == NULL || responses == NULL || context == NULL ||
        context->upstream.conv == NULL)
        return PAM_CONV_ERR;

    rewritten = calloc((size_t)count, sizeof(*rewritten));
    forwarded = calloc((size_t)count, sizeof(*forwarded));
    if (rewritten == NULL || forwarded == NULL) {
        free(rewritten);
        free(forwarded);
        return PAM_BUF_ERR;
    }

    for (index = 0; index < count; index++) {
        if (messages[index] == NULL) {
            free(forwarded);
            free(rewritten);
            return PAM_CONV_ERR;
        }
        rewritten[index] = *messages[index];
        if (rewritten[index].msg_style == PAM_TEXT_INFO &&
            rewritten[index].msg != NULL &&
            strcmp(rewritten[index].msg, action_prompt) == 0)
            rewritten[index].msg = marked_action_prompt;
        forwarded[index] = &rewritten[index];
    }

    result = context->upstream.conv(count, forwarded, responses,
                                    context->upstream.appdata_ptr);
    free(forwarded);
    free(rewritten);
    return result;
}

static void free_prompt_context(pam_handle_t *pamh, void *data, int status)
{
    struct prompt_context *context = data;
    const void *current = NULL;

    (void)status;
    if (pamh != NULL && context != NULL &&
        pam_get_item(pamh, PAM_CONV, &current) == PAM_SUCCESS &&
        current != NULL) {
        const struct pam_conv *live = (const struct pam_conv *)current;

        /* pam_set_item copies the conv; match by wrapper and appdata. */
        if (live->conv == marked_conversation && live->appdata_ptr == context)
            (void)pam_set_item(pamh, PAM_CONV, &context->upstream);
    }
    free(context);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv)
{
    const struct pam_conv *upstream;
    const void *existing;
    struct prompt_context *context;
    int result;

    (void)flags;
    (void)argc;
    (void)argv;

    if (pam_get_data(pamh, data_key, &existing) == PAM_SUCCESS)
        return PAM_IGNORE;
    if (pam_get_item(pamh, PAM_CONV, (const void **)&upstream) != PAM_SUCCESS ||
        upstream == NULL || upstream->conv == NULL)
        return PAM_IGNORE;

    context = calloc(1, sizeof(*context));
    if (context == NULL)
        return PAM_IGNORE;
    context->upstream = *upstream;
    context->replacement.conv = marked_conversation;
    context->replacement.appdata_ptr = context;

    result = pam_set_data(pamh, data_key, context, free_prompt_context);
    if (result != PAM_SUCCESS) {
        free(context);
        return PAM_IGNORE;
    }
    (void)pam_set_item(pamh, PAM_CONV, &context->replacement);
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}
