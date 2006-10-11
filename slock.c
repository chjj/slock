/* (C)opyright MMIV-MMV Anselm R. Garbe <garbeam at gmail dot com>
 * See LICENSE file for license details.
 */
#define _XOPEN_SOURCE
#include <shadow.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <X11/keysym.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

int
main(int argc, char **argv) {
	char buf[32], passwd[256];
	int num, prev_nitem;
	struct spwd *sp;
	unsigned int i, len;
	Bool running = True;
	KeySym ksym;
	Display *dpy;
	XEvent ev;

	if((argc > 1) && !strncmp(argv[1], "-v", 3)) {
		fputs("slock-"VERSION", (C)opyright MMVI Anselm R. Garbe\n", stdout);
		exit(EXIT_SUCCESS);
	}
	if(!(sp = getspnam(getenv("USER")))) {
		fputs("slock: cannot retrieve password entry (make sure to suid slock)\n", stderr);
		exit(EXIT_FAILURE);
	}
	endspent();
	if(!(dpy = XOpenDisplay(0))) {
		fputs("slock: cannot open display\n", stderr);
		exit(EXIT_FAILURE);
	}

	/* init */
	passwd[0] = 0;
	while(XGrabKeyboard(dpy, DefaultRootWindow(dpy), True, GrabModeAsync,
			 GrabModeAsync, CurrentTime) != GrabSuccess)
		usleep(1000);

	/* main event loop */
	while(running && !XNextEvent(dpy, &ev))
		if(ev.type == KeyPress) {
			len = strlen(passwd);
			buf[0] = 0;
			num = XLookupString(&ev.xkey, buf, sizeof(buf), &ksym, 0);
			if(IsFunctionKey(ksym) || IsKeypadKey(ksym)
					|| IsMiscFunctionKey(ksym) || IsPFKey(ksym)
					|| IsPrivateKeypadKey(ksym))
				continue;
			/* first check if a control mask is omitted */
			if(ev.xkey.state & ControlMask) {
				switch (ksym) {
				case XK_h:
				case XK_H: ksym = XK_BackSpace;
					break;
				case XK_u:
				case XK_U: passwd[0] = 0;
					continue;
				}
			}
			switch(ksym) {
			case XK_Return:
				running = strncmp(crypt(passwd, sp->sp_pwdp), sp->sp_pwdp, sizeof(passwd));
				passwd[0] = 0;
				break;
			case XK_Escape:
				passwd[0] = 0;
				break;
			case XK_BackSpace:
				if(len)
					passwd[--len] = 0;
				break;
			default:
				if(num && !iscntrl((int) buf[0])) {
					buf[num] = 0;
					if(len)
						strncat(passwd, buf, sizeof(passwd));
					else
						strncpy(passwd, buf, sizeof(passwd));
				}
				break;
			}
		}
	XCloseDisplay(dpy);
	return 0;
}
