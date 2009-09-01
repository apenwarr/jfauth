CC=gcc
CXX=g++
CPPFLAGS=-g -I/usr/include/xplc-0.3.13 -I/usr/include/wvstreams -Wall

default: all

all: jfauthd

jfauthd: LIBS+=-lwvstreams
jfauthd: jfauthd.o


%.o: %.cc
	$(CXX) -c -o $@ $< ${CPPFLAGS} ${CXXFLAGS}

%.o: %.c
	$(CC) -c -o $@ $< ${CPPFLAGS} ${CFLAGS}

%: %.o
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)
	
clean::
	rm -f *~ *.o jfauthd
