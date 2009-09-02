#ifndef __JFAUTH_H
#define __JFAUTH_H

// jfversion.c
#ifdef __cplusplus
extern "C" {
#endif
    extern const char *jfversion;

int jfauth_authenticate(const char *user, const char *pass);

#ifdef __cplusplus
};
#endif

#endif // _JFAUTH_H
