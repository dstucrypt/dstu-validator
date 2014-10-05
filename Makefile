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


ifeq ($(BUILD),system)
LIBS=-lcrypto -lre
INCS=-I$(RE_INC)
LIBS_STATIC=\
    $(LIB_PREFIX)/libcrypto.a \
    /usr/lib/libre.a \
    -ldl -lz -lpthread -lc
else
SSL=/usr/local/ssl
INCS=-I$(SSL)/include -I$(RE_INC)
LIBS=\
	-L$(SSL)/lib -lcrypto \
	-L$(RE_LIB) -lre
LIBS_STATIC=\
    $(SSL)/lib/libcrypto.a \
    $(RE_LIB)/libre.a
endif

CFLAGS+=-DHAVE_INET6

ifneq ($(DSTUD_VERSION),)
CFLAGS+=-DDSTUD_VERSION=\"$(DSTUD_VERSION)\"
endif

OBJS=app.o daemon.o asn1.o urldecode.o util.o

%.o: %.c
	$(CC) $< -o $@ -c $(INCS) $(CFLAGS)

authd: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LIBS) $(LDFLAGS)

authd-static: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LIBS_STATIC) $(LDFLAGS)

clean:
	rm -f $(OBJS) authd authd-static
