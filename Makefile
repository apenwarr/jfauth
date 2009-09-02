CC=gcc
CXX=g++
CPPFLAGS=-g -I/usr/include/xplc-0.3.13 -I/usr/include/wvstreams -Wall \
	-DJF_UNIX_SOCKFILE=\"/var/run/jfauthd/sock\"

_JFRELEASE:=$(shell git describe --always)
_JFDIRTY:=$(shell git diff-index --quiet --name-only HEAD || echo "-m")
JFRELEASE:=${_JFRELEASE}${_JFDIRTY}


default: all

all: jfauthd jfauth pam_jfauth.so pamtest

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
