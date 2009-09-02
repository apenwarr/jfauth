#include "jfauthd.h"
#include <wvstreams/wvstreamsdaemon.h>
#include <wvstreams/wvtcp.h>
#include <wvstreams/wvunixsocket.h>
#include <wvstreams/wvstreamclone.h>
#include <stdio.h>


class AuthStream : public WvStreamClone
{
    WvDynBuf buf;
public:
    AuthStream(IWvStream *s) : WvStreamClone(s)
    { 
	alarm(10000);
    }
    
    virtual void execute()
    {
	printf("execute\n");
	if (alarm_was_ticking)
	    close();
	else
	{
	    read(buf, 1024);
	    int ofs = buf.strchr(0);
	    if (ofs)
	    {
		WvStringList l;
		l.split(buf.getstr(ofs), "\r\n");
		int ver = l.popstr().num();
		if (ver != 1)
		{
		    WvError e;
		    e.set("Invalid version (expected 1)");
		    print("%s\r\n%s\r\n", e.get(), e.str());
		    seterr_both(e.get(), e.str());
		    return;
		}
		
		WvString user = l.popstr();
		WvString pass = l.popstr();
		printf("ver:%d user:'%s' pass:'%s' (src='%s')\n",
		       ver, user.cstr(), pass.cstr(),
		       WvString(*src()).cstr());
		WvError e = jfauth_pam("jfauthd", *src(), user, pass);
		print("%s\r\n%s\r\n", e.get(), e.str());
		close();
	    }
	    else if (buf.used() > 1024)
	    {
		printf("too much data\n");
		close();
	    }
	}
    }
};


static void tcp_incoming(WvStream &, void *userdata)
{
    printf("tcp incoming\n");
    WvTCPListener *l = (WvTCPListener *)userdata;
    WvIStreamList::globallist.append(new AuthStream(l->accept()),
				     true, (char *)"tcp_incoming");
}


static void unix_incoming(WvStream &, void *userdata)
{
    printf("unix incoming\n");
    WvUnixListener *l = (WvUnixListener *)userdata;
    WvIStreamList::globallist.append(new AuthStream(l->accept()),
				     true, (char *)"unix_incoming");
}


static void startup(WvStreamsDaemon &daemon, void *)
{
    WvTCPListener *l = new WvTCPListener(5478);
    l->setcallback(tcp_incoming, l);
    daemon.add_die_stream(l, true, (char *)"tcplistener");
    
    WvUnixListener *l2 = new WvUnixListener("/tmp/socky", 0666);
    l2->setcallback(unix_incoming, l2);
    daemon.add_die_stream(l2, true, (char *)"unixlistener");
}


int main(int argc, char **argv)
{
    WvStreamsDaemon daemon("jfauthd", "0.1", startup);
    return daemon.run(argc, argv);
}
