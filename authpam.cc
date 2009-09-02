#include "jfauthd.h"
#include <security/pam_appl.h>
#include <sys/types.h>


static int noconv(int num_msg, const struct pam_message **msgm,
		  struct pam_response **response, void *userdata)
{
    // if you need to ask things, it won't work
    return PAM_CONV_ERR;
}


// The password gets passed in from userdata, and we simply echo it back
// out in the response.  This is because pam expects this function
// to actually interact with the user, and get their password.
static int passconv(int num_msg, const struct pam_message **msgm,
		    struct pam_response **response, void *userdata)
{
    printf("passconv! (%s)\n", (char *)userdata);
    struct pam_response *password_echo;
    password_echo 
	= (struct pam_response *)calloc(num_msg, sizeof(pam_response));
    password_echo->resp = (char *)userdata;
    password_echo->resp_retcode = 0;
    *response = password_echo;
    
    return PAM_SUCCESS;
}


static WvError pamcheck(pam_handle_t *pamh, WvStringParm prefix,
			 int status, WvError &err)
{
    if (status != PAM_SUCCESS)
    {
	err.set_both(status,
		     WvString("%s: %s", prefix, pam_strerror(pamh, status)));
	return err;
    }
    else
	return WvError();
}


static void do_delay(int retval, unsigned usec_delay, void *appdata_ptr)
{
    // we do delays totally differently in jfauthd, so ignore the request
}


WvError jfauth_pam(WvStringParm appname, WvStringParm rhost,
		   WvStringParm user, WvStringParm pass)
{
    printf("authpam: (%s) (%s)\n", user.cstr(), pass.cstr());
    
    WvError err;
    pam_handle_t *pamh = NULL;
    int status;
    
    struct pam_conv c;
    c.conv = noconv;  
    c.appdata_ptr = NULL;
    
    pamh = NULL;
    status = pam_start(appname, user, &c, &pamh);
    if (!pamcheck(pamh, "pam_start", status, err).isok())
    {
	pam_end(pamh, 0);
	return err;
    }
    
    if (!!rhost)
    {
        status = pam_set_item(pamh, PAM_RHOST, rhost);
	pamcheck(pamh, "pam_set(RHOST)", status, err);
    }
    
    if (!!user)
    {
        status = pam_set_item(pamh, PAM_USER, user);
	pamcheck(pamh, "pam_set(USER)", status, err);
    }
    
    if (!!pass)
    {
        struct pam_conv c;
        c.conv = passconv;
        c.appdata_ptr = strdup(pass);
        status = pam_set_item(pamh, PAM_CONV, &c);
	pamcheck(pamh, "pam_set(CONV)", status, err);
    }
    
    status = pam_set_item(pamh, PAM_FAIL_DELAY, (const void *)do_delay);
    pamcheck(pamh, "pam_set(FAIL_DELAY)", status, err);

    status = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK | PAM_SILENT);
    pamcheck(pamh, "pam_authenticate", status, err);
    
    // supposedly needed to prevent caching between different user sessions
    pam_set_item(pamh, PAM_AUTHTOK, NULL);

    pam_end(pamh, 0);
    return err;
}
