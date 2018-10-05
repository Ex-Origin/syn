syn:main.c syn.c
	gcc -o syn main.c syn.c -lpthread -std=c99 -w -O2

all:syn
