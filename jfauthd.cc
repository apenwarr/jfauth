#include "jfauthd.h"
#include "jfauth.h"
#include "wvstreamsdaemon.h"
#include "wvtcp.h"
#include "wvunixsocket.h"
#include "wvstreamclone.h"
#include "wvfileutils.h"
#include "wvsslstream.h"
#include "wvx509.h"
#include "wvstrutils.h"
#include "wvpipe.h"
#include "wvscatterhash.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#define UNIX_TIMEOUT_MS 10000
#define TCP_TIMEOUT_MS  120000

class AuthBase;
static AuthBase *globalauth;
static WvX509Mgr *x509;

struct UserPass { WvString user, pass; time_t when, lastused; };
DeclareWvScatterDict(UserPass, WvString, user);
static UserPassDict authcache;

// config options
static WvString
    forwardhost,
    appname = "jfauthd";
static bool
    enable_tcp = false,
    enable_ssl = false,
    enable_unix = false,
    do_smbpasswd = false;
static int 
    cache_expire_secs = -1,
    cache_accel_secs = 60,
    cache_max_size = 100;


static int lru_cmp(const UserPass *a, const UserPass *b)
{
    return a->lastused - b->lastused;
}


static void authcache_add(WvStringParm user, WvStringParm pass)
{
    // FIXME: cache the password's hash instead?  If so, use a specific
    // hash designed for passwords, not just md5/sha1 (which are too fast).
    // For more, see:
    // http://www.usenix.org/events/usenix99/provos/provos_html/index.html
    // 
    // Hashing isn't so important if the cache is only in RAM, but it
    // becomes critical if we'll be persisting to disk.
    time_t now = time(NULL);
    UserPass *up = authcache[user];
    if (up && up->pass == pass)
	up->when = up->lastused = now;
    else
    {
	up = new UserPass;
	up->user = user;
	up->pass = pass;
	up->when = up->lastused = now;
	authcache.add(up, true);
    }
    
    // If the cache is too full, expire entries until it isn't.
    int cnt = authcache.count();
    if (cnt > cache_max_size)
    {
	WvList<UserPass> deathq;
	UserPassDict::Sorter i(authcache, lru_cmp);
	for (i.rewind(); i.next() && cnt > cache_max_size; cnt--)
	    deathq.append(i.ptr(), false);
	
	while (!deathq.isempty())
	{
	    authcache.remove(deathq.first());
	    deathq.unlink_first();
	}
    }
}


// expire an entry if it has the given password, because we're now sure that
// that password is wrong.  Perhaps the user has changed his password.
static void authcache_del(WvStringParm user, WvStringParm pass)
{
    UserPass *oldup = authcache[user];
    if (oldup && oldup->pass == pass)
	authcache.remove(oldup);
}


static bool authcache_check(WvStringParm user, WvStringParm pass,
			    int expire_secs)
{
    UserPass *up = authcache[user];
    time_t now = time(NULL);
    if (up && up->pass == pass
	&& (expire_secs < 0 || now - up->when < expire_secs))
    {
	up->lastused = now;
	return true;
    }
    else
	return false;
}


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
	WvError e = jfauth_pam(appname, rhost, user, pass);
	
	// If PAM has rejected it, we assume the password is *definitely*
	// wrong.  This is arguable; for example, if the LDAP server fails,
	// PAM will reject it, but we might want to cache it anyway.  But I
	// guess that should be PAM's job to consider, not ours.
	// 
	// Maybe we need to consider the PAM return code more carefully?
	if (e.isok())
	    authcache_add(user, pass);
	else
	    authcache_del(user, pass);
	
	return e;
    }
};


class ForwardAuth : public AuthBase
{
    WvString hostport;
    WvStream *s;
    WvLog log;
    bool _ok;
    
    bool connection_ok() const
        { return _ok && s && s->isok(); }
    
    void unconnect()
    {
	if (s)
	{
	    WvIStreamList::globallist.unlink(s);
	    WVRELEASE(s);
	    s = NULL;
	    _ok = false;
	}
    }
    
    void reconnect()
    {
	log(WvLog::Info, "Connecting.\n");
	unconnect();
	
	WvStream *_s;
	if (!!hostport && strchr(hostport, ':'))
	    _s = new WvTCPConn(hostport);
	else
	    _s = new WvTCPConn(hostport, 5479);
	s = new WvSSLStream(_s);
	s->runonce(0);
	s->runonce(0);
	s->alarm(5000);
	s->setcallback(_callback, this);
	WvIStreamList::globallist.append(s, false, (char *)"forwardauth");
    }
    
    void callback()
    {
	if (s->alarm_was_ticking)
	{
	    log(WvLog::Debug, "Sending keepalive.\n");
	    s->write("\0", 1); // empty keepalive message; no response expected
	    s->alarm(TCP_TIMEOUT_MS/2);
	}
	
	char buf[1024];
	size_t len = s->read(buf, sizeof(buf));
	if (len)
	{
	    log(WvLog::Warning, "Received unexpected %s bytes\n", len);
	    unconnect(); // for safety
	}
	
#if 0 
	// this isn't such a good idea; it'll cause a flood of reconnects
	// if the server ever has trouble reconnecting.  Instead, if we get
	// disconnected, *stay* disconnected until the next time someone
	// *really* needs an auth request to go through.
	if (!s->isok())
	   reconnect();
#endif
	
	// if we lived through the above, the connection is valid
	_ok = s->isok();
    }
    
    static void _callback(WvStream &, void *userdata)
    {
	ForwardAuth *auth = (ForwardAuth *)userdata;
	assert(auth->s); // it should be auth->s *calling* us, so I hope so!
	auth->callback();
    }
    
public:
    ForwardAuth(WvStringParm _hostport) 
	: hostport(_hostport), log("AuthForward", WvLog::Debug1)
    {
	s = NULL;
	_ok = false;
	reconnect();
    }
    
    ~ForwardAuth()
    {
	unconnect();
    }
    
    // Okay, this gets a little complicated with caching.  Notes:
    //  - our caller has already checked the cache for cache_accel_secs, so
    //    that has nothing to do with this logic.
    //  - if we're disconnected, use the cache up to cache_expire_secs.
    //  - if we're *not* disconnected, never read the cache, just write to it.
    virtual WvError check(WvStringParm rhost,
			  WvStringParm user, WvStringParm pass) 
    {
	if (!connection_ok())
	{
	    if (!s->isok())
		reconnect();
	    if (authcache_check(user, pass, cache_expire_secs))
		return WvError(); // pass
	    // otherwise fall through and give them another chance
	}

	WvError e;
	
	s->print("1\r\n%s\r\n%s\r\n", user, pass);
	s->write("\0", 1);
	WvString r1 = trim_string(s->getline(5000));
	WvString r2 = trim_string(s->getline(500));
	
	if (s->geterr())
	    e.set_both(s->geterr(), s->errstr());
	else if (!s->isok())
	    e.set("Remote auth server disconnected");
	else if (!r1 || !r2)
	{
	    e.set("Remote server failed to respond");
	    s->seterr_both(e.get(), e.str());
	}
	else if (r1.num())
	{
	    // explicit rejection by server: make sure the cache doesn't think
	    // this password is okay later.
	    authcache_del(user, pass);
	    e.set_both(r1.num(), r2);
	}
	else if (r1 != "0")
	    e.set("Remote auth server: syntax error in response");
	// otherwise: succeeded
	
	if (e.isok())
	    authcache_add(user, pass);
	return e;
    }
};


static void auth_succeeded(WvStringParm user, WvStringParm pass,
                           bool was_cached)
{
    if (!was_cached && do_smbpasswd && !!user && !!pass)
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
	    alarm(UNIX_TIMEOUT_MS);
	else
	    alarm(TCP_TIMEOUT_MS);
    }
    
    virtual void execute()
    {
	if (alarm_was_ticking)
	{
	    log("No recent requests: disconnecting.\n");
	    close();
	}
	else
	{
	    size_t len = read(buf, 1024);
	    if (len && multiple_requests)
		alarm(TCP_TIMEOUT_MS); // not idle, anyway
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
		WvError e;
		
		bool cache_result 
		    = authcache_check(user, pass, cache_accel_secs);
		if (!cache_result)
		    e = globalauth->check(*src(), user, pass);
		
		if (e.isok())
		{
		    log(WvLog::Info,
			"PASS: auth succeeded for user '%s'\n", user);
		    auth_succeeded(user, pass, cache_result);
		}
		else
		    log(WvLog::Notice,
			"FAIL: auth user '%s': '%s'\n", user, e.str());
		print("%s\r\n%s\r\n", e.get(), e.str());
		if (!multiple_requests)
		    close();
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
	daemon.log(WvLog::Debug, "Generating SSL certificate.\n");
	if (x509)
	    WVRELEASE(x509);
	x509 = new WvX509Mgr("jfauthd", 2048);
	
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
    
    daemon.args.add_option
	(0, "cache-time",
	 "Time to cache successful authentications for use when "
	 "forwarding server is broken (0=disable, -1=forever), "
	 "default is -1",
	 "SECONDS", cache_expire_secs);
    daemon.args.add_option
	(0, "accel-time",
	 "Time to cache successful authentications just to speed things up "
	 "(0=disable, -1=forever), default is 60",
	 "SECONDS", cache_accel_secs);
    daemon.args.add_option
	(0, "cache-size",
	 "Max number of users in the auth cache (default=100)",
	 "NUMUSERS", cache_max_size);
    
    
    daemon.args.add_set_bool_option
	('u', "unix", WvString("Listen on unix socket %s",
			       JF_UNIX_SOCKFILE), enable_unix);
    daemon.args.add_set_bool_option
	('t', "tcp", "[DANGER INSECURE] Listen on tcp port 5478", enable_tcp);
    daemon.args.add_set_bool_option
	('s', "ssl", "Listen on tcp-ssl port 5479 (encrypted)", enable_ssl);
    
    return daemon.run(argc, argv);
}
