/*
 * Simple "pwauth"-like program that authenticates via jfauthd.  This is in
 * C so it can be as tiny and fast as possible, since programs (like web
 * servers) might call out to it.
 */
#include "jfauth.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 1)
    {
	fprintf(stderr,
		"Usage: %s\n"
		"  Reads two lines from stdin: username and password.\n"
		"  Returns 0 if password validation succeeds, otherwise 1.\n",
		argv[0]);
	return 1;
    }
    
    char user[200];
    char pass[200];
    fgets(user, sizeof(user), stdin);
    fgets(pass, sizeof(pass), stdin);
    user[sizeof(user)-1] = 0;
    pass[sizeof(pass)-1] = 0;
    if (strlen(user) < 1 || strlen(pass) < 1)
	return 1;
    
    // drop trailing newlines
    user[strlen(user)-1] = 0;
    pass[strlen(pass)-1] = 0;
    
    return jfauth_authenticate(user, pass) == 0 ? 0 : 1;
}
