# Makefile

OBJS	= ace_y.o ace_l.o ace_main.o node.o

CC	= g++
CFLAGS	= -g -Wall -ansi -pedantic -Wno-write-strings 

ace:		$(OBJS)
		$(CC) $(CFLAGS) $(OBJS) -o ace -lfl

ace_l.o:		ace_l.c
		$(CC) $(CFLAGS) -c ace_l.c -o ace_l.o

ace_l.c:		ace.l 
		lex -o ace_l.c ace.l

ace_y.o:	node.o ace_y.c 
		$(CC) $(CFLAGS) node.o -c ace_y.c -o ace_y.o

ace_y.c:	ace.y
		bison -d -v -o ace_y.c ace.y

ace_main.o:		ace_main.cc
		$(CC) $(CFLAGS) -c ace_main.cc -o ace_main.o

node.o:     node.cpp
		$(CC) $(CFLAGS) -c node.cpp -o node.o

clean:
	rm -f *.o *~ ace_l.c ace_y.c ace_y.h ace_y.output ace
