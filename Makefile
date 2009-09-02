CC=gcc
CXX=g++
CPPFLAGS=-g -I/usr/include/xplc-0.3.13 -I/usr/include/wvstreams -Wall \
	-DJF_UNIX_SOCKFILE=\"/var/run/jfauthd/sock\"

_JFRELEASE:=$(shell git describe --always)
_JFDIRTY:=$(shell git diff-index --quiet --name-only HEAD || echo "-m")
JFRELEASE:=${_JFRELEASE}${_JFDIRTY}


default: all

all: jfauthd jfauth pam_jfauth.so pamtest

install: all
	install -d \
		${DESTDIR}/usr/sbin \
		${DESTDIR}/usr/bin \
		${DESTDIR}/lib/security \
		${DESTDIR}/etc/pam.d \
		${DESTDIR}/usr/share/doc/jfauth/examples
	install -m 0755 -t ${DESTDIR}/usr/sbin jfauthd
	install -m 0755 -t ${DESTDIR}/usr/bin jfauth
	install -m 0644 -t ${DESTDIR}/lib/security pam_jfauth.so
	install -m 0644 -T pam.d-jfauthd ${DESTDIR}/etc/pam.d/jfauthd
	install -m 0644 -t ${DESTDIR}/usr/share/doc/jfauth COPYING README
	install -m 0644 -T example.common-auth \
		${DESTDIR}/usr/share/doc/jfauth/examples/common-auth

jfauthd: LIBS+=-lwvstreams -lpam
jfauthd: jfauthd.o authpam.o jfversion.o

jfauth: jfauth.o libjfauth.o

jfversion.o: jfversion.c version.tmp.h

pam_jfauth.so: LIBS+=-lpam
pam_jfauth.so: pam_jfauth.o libjfauth.o
	$(CC) $(LDFLAGS) -shared -o $@ $^ $(LIBS)

pamtest: LIBS+=-lwvstreams -lpam	
pamtest: pamtest.o authpam.o

# Cheap and easy: all the .o files depend on all the .h files.
$(patsubst %.cc,%.o,$(wildcard *.cc)) $(patsubst %.c,%.o,$(wildcard *.c)): \
	$(wildcard *.h)

# This is a little convoluted, but the idea is that version.tmp.h's
# timestamp is only updated when JFRELEASE changes.  We accomplish this by
# 
.version-${JFRELEASE}: Makefile
	rm -f $@ $@.new .version-*
	echo '#define JFRELEASE "${JFRELEASE}"' >$@.new
	mv $@.new $@   
version.tmp.h: .version-${JFRELEASE}
	ln -sf $< $@

%.o: %.cc
	$(CXX) -c -o $@ $< ${CPPFLAGS} ${CXXFLAGS}

%.o: %.c
	$(CC) -c -o $@ $< ${CPPFLAGS} ${CFLAGS}

%: %.o
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)

clean::
	rm -f *~ .*~ *.o *.so jfauthd jfauth pamtest .ver* version.tmp.h
