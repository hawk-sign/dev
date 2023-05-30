CC = c99
CFLAGS = -Wall -Wextra -Wshadow -Wundef -O2
LD = $(CC)
LDFLAGS =
LIBS =

OBJCORE = hawk_kgen.o hawk_sign.o hawk_vrfy.o ng_fxp.o ng_hawk.o ng_mp31.o ng_ntru.o ng_poly.o ng_zint31.o sha3.o
HEAD = hawk.h hawk_inner.h hawk_config.h sha3.h
NG_HEAD = ng_config.h ng_inner.h sha3.h
OBJAPI = api.o
OBJEXTRA = PQCgenKAT_sign.o rng.o

all: PQCgenKAT_sign

PQCgenKAT_sign: $(OBJCORE) $(OBJAPI) $(OBJEXTRA)
	$(LD) $(LDFLAGS) -o PQCgenKAT_sign $(OBJCORE) $(OBJAPI) $(OBJEXTRA) $(LIBS)

clean:
	-rm -f $(OBJCORE) $(OBJAPI) $(OBJEXTRA) PQCgenKAT_sign

hawk_kgen.o: hawk_kgen.c $(HEAD)
	$(CC) $(CFLAGS) -c -o hawk_kgen.o hawk_kgen.c

hawk_sign.o: hawk_sign.c $(HEAD)
	$(CC) $(CFLAGS) -c -o hawk_sign.o hawk_sign.c

hawk_vrfy.o: hawk_vrfy.c $(HEAD)
	$(CC) $(CFLAGS) -c -o hawk_vrfy.o hawk_vrfy.c

ng_fxp.o: ng_fxp.c $(NG_HEAD)
	$(CC) $(CFLAGS) -c -o ng_fxp.o ng_fxp.c

ng_hawk.o: ng_hawk.c $(NG_HEAD)
	$(CC) $(CFLAGS) -c -o ng_hawk.o ng_hawk.c

ng_mp31.o: ng_mp31.c $(NG_HEAD)
	$(CC) $(CFLAGS) -c -o ng_mp31.o ng_mp31.c

ng_ntru.o: ng_ntru.c $(NG_HEAD)
	$(CC) $(CFLAGS) -c -o ng_ntru.o ng_ntru.c

ng_poly.o: ng_poly.c $(NG_HEAD)
	$(CC) $(CFLAGS) -c -o ng_poly.o ng_poly.c

ng_zint31.o: ng_zint31.c $(NG_HEAD)
	$(CC) $(CFLAGS) -c -o ng_zint31.o ng_zint31.c

sha3.o: sha3.c $(NG_HEAD)
	$(CC) $(CFLAGS) -c -o sha3.o sha3.c

api.o: api.c api.h hawk.h sha3.h
	$(CC) $(CFLAGS) -c -o api.o api.c

PQCgenKAT_sign.o: PQCgenKAT_sign.c api.h rng.h
	$(CC) $(CFLAGS) -c -o PQCgenKAT_sign.o PQCgenKAT_sign.c

rng.o: rng.c rng.h
	$(CC) $(CFLAGS) -c -o rng.o rng.c
