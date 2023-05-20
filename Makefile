
CC=gcc
CFLAGS= -std=c99 -g -D_GNU_SOURCE -Wall
LIBS= -pthread
TARGET=simpletorrent
SOURCES=src/util.c \
		src/bencode.c \
		src/sha1.c \
		src/shutdown.c \
		src/pwp.c \
		src/bitfield.c	\
		src/fileio.c \
		src/make_tracker_request.c \
		src/parse_announce_url.c \
		src/parsetorrentfile.c \
		src/process_tracker_response.c \
		src/simpletorrent.c

OBJS=$(patsubst src/%.c,obj/%.o,$(SOURCES))

all: ${TARGET}

${TARGET}: ${OBJS}
	${CC} ${CFLAGS} -o bin/${TARGET} ${LIBS} ${OBJS}

obj/%.o: src/%.c
	$(CC) -c $(CFLAGS) -o $@ $<

clean:
	rm -rf obj/*.o
	rm -rf bin/${TARGET}
	rm -rf src/*.core
	rm -rf *.o
	rm -rf ${TARGET}
	rm -rf *.core

.PHONY: all clean
