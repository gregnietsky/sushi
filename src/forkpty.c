#include <pthread.h>
#include <curses.h>
#include <term.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pty.h>
#include <utmp.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <fcntl.h>

struct vt100client {
	int	ptyfd;
	struct termios *orig_tios;
};


void hide_args(int argc, char **argv) {
	if (argc > 1) {
		char *arg_end;
		arg_end = argv[argc-1] + strlen (argv[argc-1]);
		*arg_end = ' ';
	}
}

void make_raw(int fd, struct vt100client *client) {
	struct termios stermios;

	if (tcgetattr(fd, &stermios) < 0) {
		return;
	}
	if (client->orig_tios) {
		memcpy(client->orig_tios, &stermios, sizeof(*client->orig_tios));
	}
	cfmakeraw(&stermios);
	tcsetattr(fd, TCSANOW, &stermios);
}

void set_fdflag(int fd, int newflag, int set) {
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (set) {
		fcntl(fd, F_SETFL, flags | newflag);
	} else {
		fcntl(fd, F_SETFL, flags & ~newflag);
	}
}

void *pty_thread(void *data) {
	struct vt100client *client = data;
	int mpty, len;
	char buf[512];

	mpty = client->ptyfd;

	/*bridge the pty and the client*/
	while ((len = read(mpty, &buf, sizeof(buf))) > 0) {
		if (write(STDOUT_FILENO, &buf, len) < 0) {
			break;
		}
	}
	return NULL;
}

void *stdin_thread(void *data) {
	struct vt100client *client = data;
	int len, mpty;
	char buf[512];

	mpty = client->ptyfd;

	/*bridge the pty and the client*/
	while ((len = read(STDIN_FILENO, &buf, sizeof(buf))) >  0) {
		if (write(mpty, &buf, len) < 0) {
			break;
		}
	}
	return NULL;
}

void *create_client(const char *user, const char *passwd) {
	struct vt100client *client;
	pthread_t thread1, thread2;
	struct winsize winsz;
	int mpty;
	pid_t pid;

	/*start up sushi too login and run the shell in fresh pty*/
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsz);
	if ((pid = forkpty(&mpty, NULL, NULL, &winsz)) == 0) {
		execlp("sushi", "sushi", user, passwd, NULL);
		return NULL;
	} else if (pid < 0) {
		return NULL;
	}

	if (user) {
		free((void*)user);
	}

	if (passwd) {
		memset((void*)passwd, '\0', strlen(passwd));
		free((void*)passwd);
	}

	/*configure client*/
	if (!(client = malloc(sizeof(*client)))) {
		return NULL;
	}
	client->orig_tios = malloc(sizeof(*client->orig_tios));
	client->ptyfd = mpty;

	/*set up sockets*/
	set_fdflag(client->ptyfd, O_NONBLOCK, 0);
	set_fdflag(STDIN_FILENO, O_NONBLOCK, 0);
	make_raw(STDIN_FILENO, client);

	/*start up the io bridges jouin to the pty*/
	pthread_create(&thread1, NULL, pty_thread, client);
	pthread_create(&thread2, NULL, stdin_thread, client);
	pthread_join(thread1, NULL);

	/*restore terminal settings cleanup*/
	if (client->orig_tios) {
		tcsetattr(STDIN_FILENO, TCSANOW, client->orig_tios);
		free(client->orig_tios);
	}
	free(client);
	return NULL;
}

int main(int argc, char **argv) {
	char *user, *passwd;

	user = (argv[1]) ? strdup(argv[1]) : NULL;
	passwd = (argv[2]) ? strdup(argv[2]) : NULL;
	hide_args(argc, argv);

	create_client(user, passwd);

	return 0;
}
