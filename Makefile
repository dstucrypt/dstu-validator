OS=$(shell uname -s)

ifeq ($(OS),Linux)
RE_INC=/usr/include/re
RE_LIB=/usr/lib
LFLAGS+=-Wl,-rpath=$(SSL)/lib
else
RE_INC=../libre/include
RE_LIB=../libre
endif

ifeq ($(CC),)
CC=cc
endif

SSL=/usr/local/ssl

ifeq ($(BUILD),system)
LIBS=-lcrypto -lre
INCS=-I$(RE_INC)
else
INCS=-I$(SSL)/include -I$(RE_INC)
LIBS=\
	-L$(SSL)/lib -lcrypto \
	-L$(RE_LIB) -lre
endif

CFLAGS+=-DHAVE_INET6

OBJS=app.o daemon.o asn1.o

%.o: %.c
	$(CC) $< -o $@ -c $(INCS) $(CFLAGS)

authd: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LIBS) $(LDFLAGS)

clean:
	rm -f $(OBJS) authd
