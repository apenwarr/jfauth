#include "jfauthd.h"
#include <wvstreams/wvstreamsdaemon.h>
#include <wvstreams/wvtcp.h>
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
	    if (buf.strchr(0))
	    {
		WvStringList l;
		l.split(buf.getstr(), "\r\n");
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
		printf("ver:%d user:'%s' pass:'%s'\n",
		       ver, user.cstr(), pass.cstr());
		WvError e = jfauth_pam("jfauthd", "tcp", user, pass);
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


static void incoming(WvStream &, void *userdata)
{
    printf("incoming\n");
    WvTCPListener *l = (WvTCPListener *)userdata;
    WvIStreamList::globallist.append(new AuthStream(l->accept()),
				     true, (char *)"incoming");
}


static void startup(WvStreamsDaemon &daemon, void *)
{
    WvTCPListener *l = new WvTCPListener(5478);
    l->setcallback(incoming, l);
    daemon.add_die_stream(l, true, (char *)"tcplistener");
}


int main(int argc, char **argv)
{
    WvStreamsDaemon daemon("jfauthd", "0.1", startup);
    return daemon.run(argc, argv);
}
