#include "jfauthd.h"
#include <stdio.h>

int main()
{
    printf("result1: '%s'\n",
	   jfauth_pam("jfauthd", "localhost", "apenwarr", "scs").str().cstr());
    printf("result2: '%s'\n",
	   jfauth_pam("jfauthd", "localhost", "apenwarr", "scsx").str().cstr());
    printf("result3: '%s'\n",
	   jfauth_pam("jfauthd", "localhost", "apenwarr", "scs").str().cstr());
    return 0;
}
