/* (C)opyright MMIV-MMV Anselm R. Garbe <garbeam at gmail dot com>
 * See LICENSE file for license details.
 */
#define _XOPEN_SOURCE 500

#if HAVE_SHADOW_H
#include <shadow.h>
#else
#include <pwd.h>
#endif

#include <ctype.h>
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
	char curs[] = {0, 0, 0, 0, 0, 0, 0, 0};
	char buf[32], passwd[256];
	int num, screen;
#if HAVE_SHADOW_H
	struct spwd *sp;
#else
	struct passwd *pw;
#endif
	unsigned int len;
	Bool running = True;
	Cursor invisible;
	Display *dpy;
	KeySym ksym;
	Pixmap pmap;
	Window w;
	XColor black, dummy;
	XEvent ev;
	XSetWindowAttributes wa;

	if((argc > 1) && !strncmp(argv[1], "-v", 3)) {
		fputs("slock-"VERSION", (C)opyright MMVI Anselm R. Garbe\n", stdout);
		exit(EXIT_SUCCESS);
	}
	if(geteuid() != 0) {
		fputs("slock: cannot retrieve password entry (make sure to suid slock)\n", stderr);
		exit(EXIT_FAILURE);
	}
#if HAVE_SHADOW_H
	sp = getspnam(getenv("USER"));
	endspent();
#else
	pw = getpwuid(getuid());
	endpwent();
#endif
	if(!(dpy = XOpenDisplay(0))) {
		fputs("slock: cannot open display\n", stderr);
		exit(EXIT_FAILURE);
	}
	screen = DefaultScreen(dpy);

	/* init */
	passwd[0] = 0;

	wa.override_redirect = 1;
	wa.background_pixel = BlackPixel(dpy, screen);
	w = XCreateWindow(dpy, RootWindow(dpy, screen), 0, 0,
			DisplayWidth(dpy, screen), DisplayHeight(dpy, screen),
			0, DefaultDepth(dpy, screen), CopyFromParent,
			DefaultVisual(dpy, screen), CWOverrideRedirect | CWBackPixel, &wa);

	XAllocNamedColor(dpy, DefaultColormap(dpy, screen), "black", &black, &dummy);
	pmap = XCreateBitmapFromData(dpy, w, curs, 8, 8);
	invisible = XCreatePixmapCursor(dpy, pmap, pmap, &black, &black, 0, 0);
	XDefineCursor(dpy, w, invisible);
	running = XGrabPointer(dpy, RootWindow(dpy, screen), False,
			ButtonPressMask | ButtonReleaseMask | PointerMotionMask,
			GrabModeAsync, GrabModeSync, None, invisible, CurrentTime) == GrabSuccess
		&& XGrabKeyboard(dpy, RootWindow(dpy, screen), True, GrabModeAsync,
			 GrabModeAsync, CurrentTime) == GrabSuccess;
	XMapRaised(dpy, w);
	XSync(dpy, False);

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
			switch(ksym) {
			case XK_Return:
#if HAVE_SHADOW_H
				if((running = strncmp(crypt(passwd, sp->sp_pwdp), sp->sp_pwdp, sizeof(passwd))))
#else
				if((running = strncmp(crypt(passwd, pw->pw_passwd), pw->pw_passwd, sizeof(passwd))))
#endif
					XBell(dpy, 100);
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
	XUngrabPointer(dpy, CurrentTime);
	XFreePixmap(dpy, pmap);
	XDestroyWindow(dpy, w);
	XCloseDisplay(dpy);
	return 0;
}
