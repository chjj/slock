/* See LICENSE file for license details. */
#define _XOPEN_SOURCE 500
#if HAVE_SHADOW_H
#include <shadow.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <X11/keysym.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

#if HAVE_BSD_AUTH
#include <login_cap.h>
#include <bsd_auth.h>
#endif

struct st_lock {
	int screen;
	Window root, w;
	Pixmap pmap;
};

extern const char *__progname;

static void
die(const char *errstr, ...) {
	va_list ap;

	fprintf(stderr, "%s: ", __progname);
	va_start(ap, errstr);
	vfprintf(stderr, errstr, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	fflush(stderr);

	exit(EXIT_FAILURE);
}

#ifndef HAVE_BSD_AUTH
static const char *
get_password(void) { /* only run as root */
	const char *rval;
	struct passwd *pw;

	if(geteuid() != 0)
		die("cannot retrieve password entry (make sure to suid slock)");
	pw = getpwuid(getuid());
	endpwent();
	rval =  pw->pw_passwd;

#if HAVE_SHADOW_H
	{
		struct spwd *sp;
		sp = getspnam(getenv("USER"));
		endspent();
		rval = sp->sp_pwdp;
	}
#endif

	/* drop privileges */
	if(setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0)
		die("cannot drop privileges");
	return rval;
}
#endif

static void
#ifdef HAVE_BSD_AUTH
read_password(Display *dpy)
#else
read_password(Display *dpy, const char *pws)
#endif
{
	char buf[32], passwd[256];
	int num;

	unsigned int len;
	Bool running = True;
	KeySym ksym;
	XEvent ev;

	len = 0;
	running = True;

	/* As "slock" stands for "Simple X display locker", the DPMS settings
	 * had been removed and you can set it with "xset" or some other
	 * utility. This way the user can easily set a customized DPMS
	 * timeout. */

	while(running && !XNextEvent(dpy, &ev)) {
		if(ev.type == KeyPress) {
			buf[0] = 0;
			num = XLookupString(&ev.xkey, buf, sizeof buf, &ksym, 0);
			if(IsKeypadKey(ksym)) {
				if(ksym == XK_KP_Enter)
					ksym = XK_Return;
				else if(ksym >= XK_KP_0 && ksym <= XK_KP_9)
					ksym = (ksym - XK_KP_0) + XK_0;
			}
			if(IsFunctionKey(ksym) || IsKeypadKey(ksym)
					|| IsMiscFunctionKey(ksym) || IsPFKey(ksym)
					|| IsPrivateKeypadKey(ksym))
				continue;
			switch(ksym) {
			case XK_Return:
				passwd[len] = 0;
#ifdef HAVE_BSD_AUTH
				running = !auth_userokay(getlogin(), NULL, "auth-xlock", passwd);
#else
				running = strcmp(crypt(passwd, pws), pws);
#endif
				if (running != 0)
					XBell(dpy, 100);
				len = 0;
				break;
			case XK_Escape:
				len = 0;
				break;
			case XK_BackSpace:
				if(len)
					--len;
				break;
			default:
				if(num && !iscntrl((int) buf[0]) && (len + num < sizeof passwd)) { 
					memcpy(passwd + len, buf, num);
					len += num;
				}
				break;
			}
		}
	}
}

static void
unlockscreen(Display *dpy, struct st_lock *lock) {
	if (dpy == NULL || lock == NULL)
		return;

	XUngrabPointer(dpy, CurrentTime);
	XFreePixmap(dpy, lock->pmap);
	XDestroyWindow(dpy, lock->w);

	free(lock);
}

static struct st_lock *
lockscreen(Display *dpy, int screen) {
	char curs[] = {0, 0, 0, 0, 0, 0, 0, 0};
	unsigned int len;
	struct st_lock *lock;
	Bool running = True;
	XColor black, dummy;
	XSetWindowAttributes wa;
	Cursor invisible;

	if (dpy == NULL || screen < 0)
		return NULL;

	lock = malloc(sizeof(struct st_lock));
	if (lock == NULL)
		return NULL;

	lock->screen = screen;

	lock->root = RootWindow(dpy, lock->screen);

	/* init */
	wa.override_redirect = 1;
	wa.background_pixel = BlackPixel(dpy, lock->screen);
	lock->w = XCreateWindow(dpy, lock->root, 0, 0, DisplayWidth(dpy, lock->screen), DisplayHeight(dpy, lock->screen),
			0, DefaultDepth(dpy, lock->screen), CopyFromParent,
			DefaultVisual(dpy, lock->screen), CWOverrideRedirect | CWBackPixel, &wa);
	XAllocNamedColor(dpy, DefaultColormap(dpy, lock->screen), "black", &black, &dummy);
	lock->pmap = XCreateBitmapFromData(dpy, lock->w, curs, 8, 8);
	invisible = XCreatePixmapCursor(dpy, lock->pmap, lock->pmap, &black, &black, 0, 0);
	XDefineCursor(dpy, lock->w, invisible);
	XMapRaised(dpy, lock->w);
	for(len = 1000; len; len--) {
		if(XGrabPointer(dpy, lock->root, False, ButtonPressMask | ButtonReleaseMask | PointerMotionMask,
			GrabModeAsync, GrabModeAsync, None, invisible, CurrentTime) == GrabSuccess)
			break;
		usleep(1000);
	}
	if((running = running && (len > 0))) {
		for(len = 1000; len; len--) {
			if(XGrabKeyboard(dpy, lock->root, True, GrabModeAsync, GrabModeAsync, CurrentTime)
				== GrabSuccess)
				break;
			usleep(1000);
		}
		running = (len > 0);
	}

	if (!running) {
		unlockscreen(dpy, lock);
		lock = NULL;
	}

	return lock;
}

static void
usage(void) {
	fprintf(stderr, "usage: %s -v", __progname);
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv) {
#ifndef HAVE_BSD_AUTH
	const char *pws;
#endif
	Display *dpy;
	int nscreens, screen;

	struct st_lock **locks;

	if((argc == 2) && !strcmp("-v", argv[1]))
		die("slock-%s, © 2006-2008 Anselm R Garbe", VERSION);
	else if(argc != 1)
		usage();

#ifndef HAVE_BSD_AUTH
	pws = get_password();
#endif

	if(!(dpy = XOpenDisplay(0)))
		die("cannot open display");

	/* Get the number of screens in display "dpy" and blank them all. */
	nscreens = ScreenCount(dpy);
	locks = malloc(sizeof(struct st_lock *) * nscreens);
	if (locks == NULL)
		die("malloc: %s", strerror(errno));

	for (screen = 0; screen < nscreens; screen++)
		locks[screen] = lockscreen(dpy, screen);

	XSync(dpy, False);

	/* Everything is now blank. Now wait for the correct password. */
#ifdef HAVE_BSD_AUTH
	read_password(dpy);
#else
	read_password(dpy, pws);
#endif

	/* Password ok, unlock everything and quit. */
	for (screen = 0; screen < nscreens; screen++)
		unlockscreen(dpy, locks[screen]);

	free(locks);

	XCloseDisplay(dpy);

	return 0;
}
