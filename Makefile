syn:main.c syn.c
	gcc -o syn main.c syn.c -lpthread -std=c99 -w -O2

debug:main.c syn.c
	gcc -g -o main main.c syn.c -lpthread -std=c99 

all:syn
