#include "jfauthd.h"
#include "wvstream.h"

int main()
{
    WvString user, pass;
    user = wvin->getline(-1);
    pass = wvin->getline(-1);
    wvout->print("Authenticating user '%s' (%s) with pam...\n", user, pass);
    
    WvError e = jfauth_pam("pamtest", "pamtest", user, pass);
    wvout->print("Result: '%s'\n", e.str());
    return e.get() == 0 ? 0 : 1;
}
