#ifndef __JFAUTHD_H
#define __JFAUTHD_H

#include "wverror.h"

WvError jfauth_pam(WvStringParm appname, WvStringParm rhost,
		   WvStringParm user, WvStringParm pass);

#endif // __JFAUTHD_H
