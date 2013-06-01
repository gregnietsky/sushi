/*
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <utmp.h>
#include <pty.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <limits.h>
#include <curses.h>
#include <term.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <security/pam_appl.h>

struct suses {
  const char *user;
	const char *passwd;
};

int put_clear(int c) {
	return putchar(c);
}

void hide_args(int argc, char **argv) {
	if (argc > 1) {
		char *arg_end;
		arg_end = argv[argc-1] + strlen (argv[argc-1]);
		*arg_end = ' ';
	}
}

void clean_screen(int fd) {
	int termerr;

	if (!cur_term) {
		setupterm(NULL, fd, &termerr);
		if (termerr <= 0) {
			return;
		}
		putp(tigetstr("clear"));
	}
	refresh();
}

void term_echo(int fd,int on) {
	struct termios stermios;

	if (tcgetattr(fd, &stermios) < 0) {
		printf("tcgetattr error\n");
	}

	if (!on) {
		stermios.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
		stermios.c_oflag &= ~(ONLCR);
	} else {
		stermios.c_lflag |= (ECHO | ECHOE | ECHOK | ECHONL);
		stermios.c_oflag |= (ONLCR);
	}

	if (tcsetattr(fd, TCSANOW, &stermios) < 0) {
		printf("tcgetattr error\n");
	}
}

/* im only intrested in setting the password and moving on*/
int pam_callback(int num_msg, const struct pam_message **msg,
                struct pam_response **resp, void *appdata_ptr) {
	struct pam_response *aresp;
	char buf[PAM_MAX_RESP_SIZE];
	int i;

	if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG) {
		return PAM_CONV_ERR;
	}

	if ((aresp = calloc(num_msg, sizeof(*aresp))) == NULL) {
		return PAM_BUF_ERR;
	}

	for(i = 0;i < num_msg;i++) {
		aresp[i].resp_retcode = 0;
		aresp[i].resp = NULL;
		switch (msg[i]->msg_style) {
			case PAM_PROMPT_ECHO_OFF:
				if (!appdata_ptr) {
					fputs(msg[i]->msg, stdout);
					term_echo(STDIN_FILENO, 0);
					if (fgets(buf, sizeof(buf), stdin) && (aresp[i].resp = strndup(buf, strlen(buf)-1))) {
						fprintf(stdout, "\r\n");
						term_echo(STDIN_FILENO, 1);
						break;
					}
					term_echo(STDIN_FILENO, 1);
				} else if ((aresp[i].resp = strndup((char*)appdata_ptr, PAM_MAX_RESP_SIZE-1))) {
					break;
				}
				goto fail;
			case PAM_PROMPT_ECHO_ON:
				fputs(msg[i]->msg, stdout);
				if (fgets(buf, sizeof(buf), stdin) && (aresp[i].resp = strndup(buf, strlen(buf)-1))) {
					break;
				}
				goto fail;
			case PAM_ERROR_MSG:
			case PAM_TEXT_INFO:
			default:
					goto fail;
		}
	}
	*resp = aresp;
	return PAM_SUCCESS;

fail:
	memset(aresp, 0, sizeof(*aresp)*num_msg);
	free(aresp);
	*resp = NULL;
	return PAM_CONV_ERR;
}

/* authenticate a user as painless as possible*/
int pam_authuser(const char *session, const char **user, const char *passwd) {
	const char *auser;
	pam_handle_t *handle;
	struct pam_conv conv = {NULL,NULL};
	int pamerr;

	conv.conv = &pam_callback;
	if (passwd && !(conv.appdata_ptr = strdup(passwd))) {
		return PAM_BUF_ERR;
	}

	auser = (user && *user) ? *user : NULL;

	if ((pamerr = pam_start(session, auser, &conv, &handle))) {
		memset(conv.appdata_ptr, 0, strlen((char*)conv.appdata_ptr));
		free(conv.appdata_ptr);
		return pamerr;
	}

	pamerr = pam_authenticate(handle, PAM_DISALLOW_NULL_AUTHTOK | PAM_SILENT);
	if (conv.appdata_ptr) {
		memset(conv.appdata_ptr, 0, strlen((char*)conv.appdata_ptr));
		free(conv.appdata_ptr);
		conv.appdata_ptr = NULL;
	}

	if (pamerr) {
		pam_end(handle, pamerr);
		return pamerr;
	}

	if (user && !*user) {
		pamerr = pam_get_item(handle, PAM_USER, (const void**)user);
	}
	return pamerr;
}

void clear_ses(struct suses *sesinf) {
	if (sesinf->user) {
		free((void*)sesinf->user);
		sesinf->user = NULL;
	}
	if (sesinf->passwd) {
		memset((void*)sesinf->passwd, '\0', strlen(sesinf->passwd));
		free((void*)sesinf->passwd);
		sesinf->passwd = NULL;
	}
}

int main(int argc, char **argv) {
	struct suses sesinf;
	gid_t admin[] = {0, 139, 4};
	struct passwd pwent, *pwres;
	char pwbuf[1024];
	int grcnt, cnt, cnt2, ret;
	gid_t *grlist;
	uid_t ruid, euid;
	gid_t rgid, egid;
	pid_t fpid;

	sesinf.user = (argc > 1) ? strdup(argv[1]) : NULL;
	sesinf.passwd = (argc > 2) ? strdup(argv[2]) : NULL;
	if (argv[2]) {
		memset(argv[2], '*', strlen(argv[2]));
	}
	hide_args(argc, argv);
	clean_screen(STDOUT_FILENO);

	/*need a pam verification*/
	if (pam_authuser(argv[0], &sesinf.user, sesinf.passwd) != PAM_SUCCESS) {
		clear_ses(&sesinf);
		return -1;
	}

	/*set the real uid/gid to authenticated user we must be a valid user*/
	if (getpwnam_r(sesinf.user, &pwent, pwbuf, sizeof(pwbuf), &pwres) || !pwres) {
		clear_ses(&sesinf);
		return -2;
	}
	clear_ses(&sesinf);
	ruid = pwres->pw_uid;
	rgid = pwres->pw_gid;

	/*get the user we suid/sgid to*/
	euid = geteuid();
	egid = getegid();

	/*load groups for logged in user if not ruid*/
	if ((ruid != geteuid()) && initgroups(pwres->pw_name, rgid)) {
		return -3;
	}

	/*determine if we can remain super user checking admin groups list*/
	if ((grcnt = getgroups(0, NULL))) {
		int issu = 0;
		int sucnt = sizeof(admin)/sizeof(gid_t);

		if (!(grlist = calloc(grcnt, sizeof(*grlist))))  {
			return -4;
		}

		if (getgroups(grcnt, grlist) < 0) {
			free(grlist);
			return -5;
		}

		for(cnt=0; cnt < grcnt && !issu;cnt++) {
			for(cnt2=0; cnt2 < sucnt;cnt2++) {
				if (admin[cnt2] == grlist[cnt]) {
					issu = 1;
					break;
				}
			}
		}
		free(grlist);

		/* use the setuid/setgid id's if we a SU*/
		if (issu && (euid != ruid)) {
			ruid=euid;
			rgid=egid;
			/*set the pwent to be for euid this is who we loging in as and must exist*/
			if (getpwuid_r(euid, &pwent, pwbuf, sizeof(pwbuf), &pwres) || !pwres) {
				return -6;
			}
		}
	}

	/*setup real user/gid to match effective*/
	if (setregid(egid, -1) || setreuid(euid, -1)) {
		return -7;
	}

	/* chdir to home*/
	if (chdir(pwres->pw_dir)) {
		return -8;
	}

	/*run login to do the rest no need to re implement the wheel ??*/
	if ((fpid = fork()) == 0) {
		newterm(NULL, stdout, stdin);
		clean_screen(STDOUT_FILENO);
		execlp("login", "login", "-f" ,pwres->pw_name, NULL);
	} if (fpid < 0) {
		return -9;
	}
	newterm(NULL, stdout, stdin);
	waitpid(fpid, &ret, 0);
	clean_screen(STDOUT_FILENO);

	if (WIFEXITED(ret)) {
		ret = WEXITSTATUS(ret);
	} else {
		ret = -9;
	}
	endwin();
	return ret;
}
