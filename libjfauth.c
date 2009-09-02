#include "jfauth.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int jfauth_authenticate(const char *user, const char *pass)
{
    int sock = socket(PF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
    {
	perror("socket");
	return -1;
    }
    
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, JF_UNIX_SOCKFILE, sizeof(sa.sun_path));
    int ret = connect(sock, (struct sockaddr *)&sa,
		      sizeof(sa.sun_family)+strlen(JF_UNIX_SOCKFILE));
    if (ret != 0)
    {
	perror("connect");
	return -1;
    }
    
    char buf[1024];
    buf[1023] = 0;
    snprintf(buf, sizeof(buf)-1, "1\r\n%s\r\n%s\r\n", user, pass);
    ret = write(sock, buf, strlen(buf)+1);
    if (ret != strlen(buf)+1)
    {
	perror("write");
	return -1;
    }
    
    char rc[3] = "";
    ret = read(sock, &rc, 3);
    if (ret != 3)
    {
	perror("read");
	return -1;
    }
    
    close(sock);
    
    return !strncmp(rc, "0\r\n", 3) ? 0 : -1;
}


