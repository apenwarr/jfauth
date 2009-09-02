CC=gcc
CXX=g++
CPPFLAGS=-g -I/usr/include/xplc-0.3.13 -I/usr/include/wvstreams -Wall \
	-DJF_UNIX_SOCKFILE=\"/var/run/jfauthd/sock\"

default: all

all: jfauthd jfauth pam_jfauth.so pamtest

jfauthd: LIBS+=-lwvstreams -lpam
jfauthd: jfauthd.o authpam.o

jfauth: jfauth.o libjfauth.o

pam_jfauth.so: LIBS+=-lpam
pam_jfauth.so: pam_jfauth.o libjfauth.o
	$(CC) $(LDFLAGS) -shared -o $@ $^ $(LIBS)

pamtest: LIBS+=-lwvstreams -lpam	
pamtest: pamtest.o authpam.o

# Cheap and easy: all the .o files depend on all the .h files.
$(patsubst %.cc,%.o,$(wildcard *.cc)) $(patsubst %.c,%.o,$(wildcard *.c)): \
	$(wildcard *.h)

%.o: %.cc
	$(CXX) -c -o $@ $< ${CPPFLAGS} ${CXXFLAGS}

%.o: %.c
	$(CC) -c -o $@ $< ${CPPFLAGS} ${CFLAGS}

%: %.o
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)
	
clean::
	rm -f *~ .*~ *.o *.so jfauthd jfauth pamtest
