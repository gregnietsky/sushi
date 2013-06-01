ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = sushi forkpty

sushi_SOURCES = sushi.c
sushi_LDADD = -lpam -lncurses

forkpty_SOURCES = forkpty.c
forkpty_LDADD = -lpthread -lutil

install-exec-hook:
	chown root.root $(DESTDIR)${bindir}/sushi${EXEXT}
	chmod 6755 $(DESTDIR)${bindir}/sushi${EXEXT}
