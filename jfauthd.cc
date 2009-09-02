#include "jfauthd.h"
#include "wvstreamsdaemon.h"
#include "wvtcp.h"
#include "wvunixsocket.h"
#include "wvstreamclone.h"
#include "wvfileutils.h"
#include "wvsslstream.h"
#include "wvx509mgr.h"
#include "wvstrutils.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#define JF_UNIX_SOCKFILE "/var/run/jfauthd/sock"
    
class AuthStream : public WvStreamClone
{
    WvDynBuf buf;
    WvLog log;
    bool multiple_requests;
public:
    AuthStream(IWvStream *s, bool _multiple_requests)
	: WvStreamClone(s), log(*src(), WvLog::Info)
    { 
	multiple_requests = _multiple_requests;
	if (!multiple_requests)
	    alarm(10000);
	else
	    alarm(60000);
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
		WvString instr = trim_string(buf.getstr(ofs).edit());
		if (!instr)
		    return;
		l.split(instr, "\r\n");
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
		if (!multiple_requests)
		    close();
		else
		    alarm(60000);
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
    WvIStreamList::globallist.append(new AuthStream(l->accept(), true),
				     true, (char *)"tcp_incoming");
}


static void ssl_incoming(WvStream &, void *userdata)
{
    printf("ssl incoming\n");
    WvTCPListener *l = (WvTCPListener *)userdata;
    WvX509Mgr *x509 = new WvX509Mgr("jfauthd", 2048);
    WvSSLStream *ssl = new WvSSLStream(l->accept(), x509, 0, true);
    WvIStreamList::globallist.append(new AuthStream(ssl, true),
				     true, (char *)"ssl_incoming");
}


static void unix_incoming(WvStream &, void *userdata)
{
    printf("unix incoming\n");
    WvUnixListener *l = (WvUnixListener *)userdata;
    WvIStreamList::globallist.append(new AuthStream(l->accept(), false),
				     true, (char *)"unix_incoming");
}


static void startup(WvStreamsDaemon &daemon, void *)
{
    WvTCPListener *tcp = new WvTCPListener(5478);
    tcp->setcallback(tcp_incoming, tcp);
    daemon.add_die_stream(tcp, true, (char *)"tcplistener");
    
    WvTCPListener *ssl = new WvTCPListener(5479);
    ssl->setcallback(ssl_incoming, ssl);
    daemon.add_die_stream(ssl, true, (char *)"ssllistener");
    
    mkdirp("/var/run/jfauthd", 0755);
    WvUnixListener *unixl = new WvUnixListener(JF_UNIX_SOCKFILE, 0666);
    chmod(JF_UNIX_SOCKFILE, 0666);
    unixl->setcallback(unix_incoming, unixl);
    daemon.add_die_stream(unixl, true, (char *)"unixlistener");
}


int main(int argc, char **argv)
{
    WvStreamsDaemon daemon("jfauthd", "0.1", startup);
    return daemon.run(argc, argv);
}
