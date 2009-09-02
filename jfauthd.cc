#include "jfauthd.h"
#include <wvstreams/wvstreamsdaemon.h>
#include <wvstreams/wvtcp.h>
#include <wvstreams/wvunixsocket.h>
#include <wvstreams/wvstreamclone.h>
#include <wvstreams/wvfileutils.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#define JF_UNIX_SOCKFILE "/var/run/jfauthd/sock"
    
class AuthStream : public WvStreamClone
{
    WvDynBuf buf;
    WvLog log;
public:
    AuthStream(IWvStream *s) 
	: WvStreamClone(s), log(*src(), WvLog::Info)
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
		log(WvLog::Debug1, "auth request for user '%s'\n", user);
		printf("ver:%d user:'%s' pass:'%s' (src='%s')\n",
		       ver, user.cstr(), pass.cstr(),
		       WvString(*src()).cstr());
		WvError e = jfauth_pam("jfauthd", *src(), user, pass);
		if (e.isok())
		    log(WvLog::Info,
			"PASS: auth succeeded for user '%s'\n", user);
		else
		    log(WvLog::Notice,
			"FAIL: auth user '%s': '%s'\n", user, e.str());
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
    
    mkdirp("/var/run/jfauthd", 0755);
    WvUnixListener *l2 = new WvUnixListener(JF_UNIX_SOCKFILE, 0666);
    chmod(JF_UNIX_SOCKFILE, 0666);
    l2->setcallback(unix_incoming, l2);
    daemon.add_die_stream(l2, true, (char *)"unixlistener");
}


int main(int argc, char **argv)
{
    WvStreamsDaemon daemon("jfauthd", "0.1", startup);
    return daemon.run(argc, argv);
}
