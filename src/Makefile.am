ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = sushi sushipty

sushi_SOURCES = sushi.c
sushipty_SOURCES = sushipty.c

install-exec-hook:
	chown root.root $(DESTDIR)${bindir}/sushi${EXEXT}
	chmod 6755 $(DESTDIR)${bindir}/sushi${EXEXT}
