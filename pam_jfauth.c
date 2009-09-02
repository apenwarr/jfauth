#include "jfauth.h"
#include <stdio.h>
#include <malloc.h>
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
				   int argc, const char **argv)
{
    printf("pam_sm_auth!\n");
    
    int ret;
    const char *name, *pass;
    
    ret = pam_get_user(pamh, &name, NULL);
    if (ret != PAM_SUCCESS)
	return PAM_AUTH_ERR;
    
    ret = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pass);
    if (ret == PAM_SUCCESS)
    {
	// if there's an existing auth token, try it!
	if (jfauth_authenticate(name, pass) == 0)
	    return 0;
    }
    
    printf("authtok didn't work\n");
    
    // if we get here, there was either no auth token or it didn't succeed;
    // let's try the conversation function instead.
    struct pam_conv *c = NULL;
    ret = pam_get_item(pamh, PAM_CONV, (const void **)&c);
    printf("conv=%p\n", c);
    if (ret != PAM_SUCCESS)
	return PAM_AUTH_ERR;
    
    struct pam_message m[] = {
	{ PAM_PROMPT_ECHO_OFF, "Password:" },
    };
    struct pam_response *resp;
    ret = c->conv(1, (const struct pam_message **)&m, &resp, c->appdata_ptr);
    printf("convresult=%d %p\n", ret, resp);
    if (ret != PAM_SUCCESS)
	return ret;
    pass = resp[0].resp;
    printf("pass is (%s)\n", pass);
    
    int result = jfauth_authenticate(name, pass) == 0;
    
    free(resp[0].resp);
    free(resp);
    
    return result ? PAM_SUCCESS : PAM_AUTH_ERR;
}


PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,
			      int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh,
				int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
				int argc, const char **argv)
{
    return PAM_IGNORE;
}


PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
				   int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,
				    int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

/* static module data */
#ifdef PAM_STATIC
struct pam_module _pam_jfauth_modstruct = {
	"pam_jfauth",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok,
};
#endif
