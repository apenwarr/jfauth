#include "jfauthd.h"
#include "jfauth.h"
#include "wvstreamsdaemon.h"
#include "wvtcp.h"
#include "wvunixsocket.h"
#include "wvstreamclone.h"
#include "wvfileutils.h"
#include "wvsslstream.h"
#include "wvx509mgr.h"
#include "wvstrutils.h"
#include "wvpipe.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

class AuthBase;
AuthBase *globalauth;

static WvString forwardhost, appname = "jfauthd";
static bool enable_tcp = false, enable_ssl = false, enable_unix = false,
    do_smbpasswd = false;


class AuthBase
{
public:
    virtual WvError check(WvStringParm rhost,
			  WvStringParm user, WvStringParm pass) = 0;
    
    virtual ~AuthBase() {}
};


class PamAuth : public AuthBase
{
public:
    virtual WvError check(WvStringParm rhost,
			  WvStringParm user, WvStringParm pass) 
    {
	return jfauth_pam(appname, rhost, user, pass);
    }
};


class ForwardAuth : public AuthBase
{
    WvString hostport;
    WvStream *s;
    
    void unconnect()
    {
	if (s)
	{
	    WvIStreamList::globallist.unlink(s);
	    WVRELEASE(s);
	    s = NULL;
	}
    }
    
    void reconnect()
    {
	unconnect();
	
	WvStream *_s;
	if (!!hostport && strchr(hostport, ':'))
	    _s = new WvTCPConn(hostport);
	else
	    _s = new WvTCPConn(hostport, 5479);
	s = new WvSSLStream(_s);
	WvIStreamList::globallist.append(s, false, (char *)"forwardauth");
    }
    
public:
    ForwardAuth(WvStringParm _hostport) 
	: hostport(_hostport)
    {
	s = NULL;
	reconnect();
    }
    
    ~ForwardAuth()
    {
	unconnect();
    }
    
    virtual WvError check(WvStringParm rhost,
			  WvStringParm user, WvStringParm pass) 
    {
	if (!s->isok())
	    reconnect();
	
	s->print("1\r\n%s\r\n%s\r\n", user, pass);
	s->write("\0", 1);
	s->runonce(0);
	WvString r1 = trim_string(s->getline(5000));
	WvString r2 = trim_string(s->getline(500));
	
	WvError e;
	if (s->geterr())
	    e.set_both(s->geterr(), s->errstr());
	else if (!s->isok())
	    e.set("Remote auth server disconnected");
	else if (r1.num())
	    e.set_both(r1.num(), r2);
	else if (r1 != "0")
	    e.set("Remote auth server: syntax error in response");
	// otherwise: succeeded
	 
	return e;
    }
};


static void auth_succeeded(WvStringParm user, WvStringParm pass)
{
    if (do_smbpasswd && !!user && !!pass)
    {
	const char *argv[] = { "smbpasswd", "-a", "-s", user, NULL };
	WvPipe p("smbpasswd", argv, true, false, false);
	p.print("%s\n%s\n", pass, pass);
	p.nowrite();
	p.finish(false);
	int ret = p.exit_status();
	if (ret)
	{
	    WvLog("smbpasswd", WvLog::Warning)
		.print("smbpasswd returned error code %s\n", ret);
	}
    }
}


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
		
		assert(globalauth);
		WvError e = globalauth->check(*src(), user, pass);
		
		if (e.isok())
		{
		    log(WvLog::Info,
			"PASS: auth succeeded for user '%s'\n", user);
		    auth_succeeded(user, pass);
		}
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
		log(WvLog::Warning, "too much data received: attacker?\n");
		close();
	    }
	}
    }
};


static void tcp_incoming(WvStream &, void *userdata)
{
    WvTCPListener *l = (WvTCPListener *)userdata;
    WvIStreamList::globallist.append(new AuthStream(l->accept(), true),
				     true, (char *)"tcp_incoming");
}


static void ssl_incoming(WvStream &, void *userdata)
{
    WvTCPListener *l = (WvTCPListener *)userdata;
    WvX509Mgr *x509 = new WvX509Mgr("jfauthd", 2048);
    WvSSLStream *ssl = new WvSSLStream(l->accept(), x509, 0, true);
    WvIStreamList::globallist.append(new AuthStream(ssl, true),
				     true, (char *)"ssl_incoming");
}


static void unix_incoming(WvStream &, void *userdata)
{
    WvUnixListener *l = (WvUnixListener *)userdata;
    WvIStreamList::globallist.append(new AuthStream(l->accept(), false),
				     true, (char *)"unix_incoming");
}


static void startup(WvStreamsDaemon &daemon, void *)
{
    if (!enable_tcp && !enable_ssl && !enable_unix)
    {
	daemon.log(WvLog::Critical, "Must specify one of -u, -t, -s\n");
	return;
    }
    
    if (do_smbpasswd && getuid() != 0)
	daemon.log(WvLog::Warning, 
	   "smbpasswd updates enabled, but jfauthd not running as root\n");
    
    if (globalauth)
	delete globalauth;
    if (forwardhost)
	globalauth = new ForwardAuth(forwardhost);
    else
	globalauth = new PamAuth();
    
    if (enable_tcp)
    {
	WvTCPListener *tcp = new WvTCPListener(5478);
	tcp->setcallback(tcp_incoming, tcp);
	daemon.add_die_stream(tcp, true, (char *)"tcplistener");
    }
    
    if (enable_ssl)
    {
	WvTCPListener *ssl = new WvTCPListener(5479);
	ssl->setcallback(ssl_incoming, ssl);
	daemon.add_die_stream(ssl, true, (char *)"ssllistener");
    }
    
    if (enable_unix)
    {
	mkdirp("/var/run/jfauthd", 0755);
	WvUnixListener *unixl = new WvUnixListener(JF_UNIX_SOCKFILE, 0666);
	chmod(JF_UNIX_SOCKFILE, 0666);
	unixl->setcallback(unix_incoming, unixl);
	daemon.add_die_stream(unixl, true, (char *)"unixlistener");
    }
}


int main(int argc, char **argv)
{
    WvStreamsDaemon daemon("jfauthd", jfversion, startup);
    
    daemon.args.add_option
	('f', "forward", "Forward all requests to a remote jfauthd",
	 "HOST:PORT", forwardhost);
    daemon.args.add_option
	('n', "name", "Change the PAM appname (default is 'jfauthd')",
	 "APPNAME", appname);
    
    daemon.args.add_set_bool_option
	(0, "smbpasswd", "Auto-update smbpasswd on successful auth",
	 do_smbpasswd);
    
    daemon.args.add_set_bool_option
	('u', "unix", WvString("Listen on unix socket %s",
			       JF_UNIX_SOCKFILE), enable_unix);
    daemon.args.add_set_bool_option
	('t', "tcp", "[DANGER INSECURE] Listen on tcp port 5478", enable_tcp);
    daemon.args.add_set_bool_option
	('s', "ssl", "Listen on tcp-ssl port 5479 (encrypted)", enable_ssl);
    
    return daemon.run(argc, argv);
}
