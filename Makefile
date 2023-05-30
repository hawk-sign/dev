# This Makefile compiles the implementation in this directory.
.PHONY: avx2 ref
.POSIX:

all: build avx2 ref

build: src/*
	./build.py
avx2:
	make -C Optimized_Implementation/avx2
ref:
	make -C Reference_Implementation
