/*
 * Simple "pwauth"-like program that authenticates via jfauthd.  This is in
 * C so it can be as tiny and fast as possible, since programs (like web
 * servers) might call out to it.
 */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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
    
    int sock = socket(PF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
    {
	perror("socket");
	return 1;
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
	return 1;
    }
    
    char buf[1024];
    buf[1023] = 0;
    snprintf(buf, sizeof(buf)-1, "1\r\n%s\r\n%s\r\n", user, pass);
    ret = write(sock, buf, strlen(buf)+1);
    if (ret != strlen(buf)+1)
    {
	perror("write");
	return 1;
    }
    
    char rc[3] = "";
    ret = read(sock, &rc, 3);
    if (ret != 3)
    {
	perror("read");
	return 1;
    }
    
    close(sock);
    
    return !strncmp(rc, "0\r\n", 3) ? 0 : 1;
}
