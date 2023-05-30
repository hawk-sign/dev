# This Makefile compiles the implementation in this directory.
.POSIX:

CC = c99
CFLAGS = -Wall -Wextra -Wshadow -Wundef -O2 -fdiagnostics-color=always
CXXFLAGS = --std=c++17 $(CFLAGS)
LIBS = -lm -lpthread

OBJ = build/hawk_kgen.o build/hawk_sign.o build/hawk_vrfy.o build/ng_fxp.o build/ng_hawk.o build/ng_mp31.o build/ng_ntru.o build/ng_poly.o build/ng_zint31.o build/sha3.o
PROGS = \
	bin/test_self bin/speed \
	bin/sig_size bin/skpk_size bin/nearest_plane

HEAD = hawk.h hawk_inner.h hawk_config.h sha3.h
NG_HEAD = ng_config.h ng_inner.h sha3.h

all: build bin $(PROGS)

build:
	-mkdir -p build
bin:
	-mkdir -p bin

clean:
	-rm -f $(OBJ) $(PROGS)

# Binaries:

# C
bin/test_self: tests/test_self.c $(OBJ)
	$(CC) $(CFLAGS) -o bin/test_self tests/test_self.c $(OBJ)
bin/speed: tests/speed.c $(OBJ)
	$(CC) $(CFLAGS) -o bin/speed tests/speed.c $(OBJ)

# C++
bin/sig_size: tests/sig_size.cpp $(OBJ)
	$(CXX) $(CXXFLAGS) -o bin/sig_size tests/sig_size.cpp $(filter-out build/hawk_sign.o,$(OBJ)) $(LIBS)
bin/skpk_size: tests/skpk_size.cpp $(OBJ)
	$(CXX) $(CXXFLAGS) -o bin/skpk_size tests/skpk_size.cpp $(filter-out build/hawk_kgen.o,$(OBJ)) $(LIBS)
bin/nearest_plane: tests/nearest_plane.cpp $(OBJ)
	$(CXX) $(CXXFLAGS) -o bin/nearest_plane tests/nearest_plane.cpp $(filter-out build/hawk_kgen.o,$(OBJ)) $(LIBS)

# Object files:
build/hawk_kgen.o: hawk_kgen.c $(HEAD)
	$(CC) $(CFLAGS) -c -o build/hawk_kgen.o hawk_kgen.c
build/hawk_sign.o: hawk_sign.c $(HEAD) modq.h
	$(CC) $(CFLAGS) -c -o build/hawk_sign.o hawk_sign.c
build/hawk_vrfy.o: hawk_vrfy.c $(HEAD)
	$(CC) $(CFLAGS) -c -o build/hawk_vrfy.o hawk_vrfy.c
build/ng_fxp.o: ng_fxp.c $(NG_HEAD)
	$(CC) $(CFLAGS) -c -o build/ng_fxp.o ng_fxp.c
build/ng_hawk.o: ng_hawk.c $(NG_HEAD)
	$(CC) $(CFLAGS) -c -o build/ng_hawk.o ng_hawk.c
build/ng_mp31.o: ng_mp31.c $(NG_HEAD)
	$(CC) $(CFLAGS) -c -o build/ng_mp31.o ng_mp31.c
build/ng_ntru.o: ng_ntru.c $(NG_HEAD)
	$(CC) $(CFLAGS) -c -o build/ng_ntru.o ng_ntru.c
build/ng_poly.o: ng_poly.c $(NG_HEAD)
	$(CC) $(CFLAGS) -c -o build/ng_poly.o ng_poly.c
build/ng_zint31.o: ng_zint31.c $(NG_HEAD)
	$(CC) $(CFLAGS) -c -o build/ng_zint31.o ng_zint31.c
build/sha3.o: sha3.c $(NG_HEAD)
	$(CC) $(CFLAGS) -c -o build/sha3.o sha3.c
