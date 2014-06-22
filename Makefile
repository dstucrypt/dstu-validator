RE=../libre

INCS=-I$(RE)/include -I/usr/local/ssl/include
LIBS=-L$(RE) -lre -L/usr/local/ssl/lib -lcrypto
CFLAGS=-DHAVE_INET6

OBJS=app.o daemon.o asn1.o

%.o: %.c
	cc $< -o $@ -c $(INCS) $(CFLAGS) -g

authd: $(OBJS)
	cc $(OBJS) -o $@ $(LIBS) -g
