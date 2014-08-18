
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
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <X11/keysym.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

#if HAVE_BSD_AUTH
#include <login_cap.h>
#include <bsd_auth.h>
#endif

#define SLOCK_SHUTDOWN 1

char *g_pw = NULL;
int alt_kill = 1;
int lock_tries = 0;

typedef struct {
	int screen;
	Window root, win;
	Pixmap pmap;
	unsigned long colors[2];
} Lock;

static Lock **locks;
static int nscreens;
static Bool running = True;

static void
die(const char *errstr, ...) {
	va_list ap;

	va_start(ap, errstr);
	vfprintf(stderr, errstr, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

#ifdef __linux__
#include <fcntl.h>

static void
dontkillme(void) {
	int fd;

	fd = open("/proc/self/oom_score_adj", O_WRONLY);
	if (fd < 0 && errno == ENOENT)
		return;
	if (fd < 0 || write(fd, "-1000\n", 6) != 6 || close(fd) != 0)
		fprintf(stderr, "cannot disable the out-of-memory killer for this process\n");
}
#endif

#ifndef HAVE_BSD_AUTH

static const char *
getpw(void) { /* only run as root */
	const char *rval;
	struct passwd *pw;

	if(g_pw)
		return g_pw;

	errno = 0;
	pw = getpwuid(getuid());
	if (!pw) {
		if (errno)
			die("slock: getpwuid: %s\n", strerror(errno));
		else
			die("slock: cannot retrieve password entry (make sure to suid or sgid slock)\n");
	}
	endpwent();
	rval =  pw->pw_passwd;

#if HAVE_SHADOW_H
	if (rval[0] == 'x' && rval[1] == '\0') {
		struct spwd *sp;
		sp = getspnam(getenv("USER"));
		if(!sp)
			die("slock: cannot retrieve shadow entry (make sure to suid or sgid slock)\n");
		endspent();
		rval = sp->sp_pwdp;
	}
#endif

	/* drop privileges */
	if (geteuid() == 0
	   && ((getegid() != pw->pw_gid && setgid(pw->pw_gid) < 0) || setuid(pw->pw_uid) < 0))
		die("slock: cannot drop privileges\n");
	return rval;
}
#endif

static void
#ifdef HAVE_BSD_AUTH
readpw(Display *dpy)
#else
readpw(Display *dpy, const char *pws)
#endif
{
	char buf[32], passwd[256];
	int num, screen;
	unsigned int len, llen;
	KeySym ksym;
	XEvent ev;

	len = llen = 0;
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
				if(g_pw) {
					running = !!strcmp(passwd, g_pw);
				} else {
					running = !!strcmp(crypt(passwd, pws), pws);
				}
#endif
				if(running) {
					XBell(dpy, 100);
					lock_tries++;
					#include "twilio.c"
#if SLOCK_SHUTDOWN
					if(lock_tries > 5) {
						// Needs sudo privileges for systemctl
						char *args[] = { "sudo", "systemctl", "poweroff", NULL };
						execvp("sudo", args);
						// if we failed, simply resume
						len = 0;
						break;
					}
#endif
					if(lock_tries > 2) {
						// http://soundbible.com/1819-Police.html
						char snd[255] = {0};
						snprintf(snd, sizeof(snd), "aplay %s/slock/police.wav", getenv("HOME"));
						system(snd);
					} else {
						char snd[255] = {0};
						snprintf(snd, sizeof(snd), "aplay %s/slock/beep.wav", getenv("HOME"));
						system(snd);
					}
				} else {
					// http://soundbible.com/1815-A-Tone.html
					char snd[255] = {0};
					snprintf(snd, sizeof(snd), "aplay %s/slock/beep.wav &", getenv("HOME"));
					system(snd);
				}
				len = 0;
				break;
			case XK_Escape:
				len = 0;
				break;
			case XK_BackSpace:
				if(len)
					--len;
				break;
#if SLOCK_SHUTDOWN
			case XK_Alt_L:
			case XK_Alt_R:
			case XK_Control_L:
			case XK_Control_R:
			case XK_F1:
			case XK_F2:
			case XK_F3:
			case XK_F4:
			case XK_F5:
			case XK_F6:
			case XK_F7:
			case XK_F8:
			case XK_F9:
			case XK_F10:
			case XK_F11:
			case XK_F12:
			case XK_F13:
				// Needs sudo privileges for systemctl
				if (alt_kill) {
					char *args[] = { "sudo", "systemctl", "poweroff", NULL };
					execvp("sudo", args);
					// fall-through if we fail
				}
#endif
			default:
				if(num && !iscntrl((int) buf[0]) && (len + num < sizeof passwd)) {
					memcpy(passwd + len, buf, num);
					len += num;
				}
				break;
			}
			if(llen == 0 && len != 0) {
				for(screen = 0; screen < nscreens; screen++) {
					XSetWindowBackground(dpy, locks[screen]->win, locks[screen]->colors[1]);
					XClearWindow(dpy, locks[screen]->win);
				}
			} else if(llen != 0 && len == 0) {
				for(screen = 0; screen < nscreens; screen++) {
					XSetWindowBackground(dpy, locks[screen]->win, locks[screen]->colors[0]);
					XClearWindow(dpy, locks[screen]->win);
				}
			}
			llen = len;
		}
		else for(screen = 0; screen < nscreens; screen++)
			XRaiseWindow(dpy, locks[screen]->win);
	}
}

static void
unlockscreen(Display *dpy, Lock *lock) {
	if(dpy == NULL || lock == NULL)
		return;

	XUngrabPointer(dpy, CurrentTime);
	XFreeColors(dpy, DefaultColormap(dpy, lock->screen), lock->colors, 2, 0);
	XFreePixmap(dpy, lock->pmap);
	XDestroyWindow(dpy, lock->win);

	free(lock);
}

static Lock *
lockscreen(Display *dpy, int screen) {
	char curs[] = {0, 0, 0, 0, 0, 0, 0, 0};
	unsigned int len;
	Lock *lock;
	XColor color, dummy;
	XSetWindowAttributes wa;
	Cursor invisible;

	if(dpy == NULL || screen < 0)
		return NULL;

	lock = malloc(sizeof(Lock));
	if(lock == NULL)
		return NULL;

	lock->screen = screen;

	lock->root = RootWindow(dpy, lock->screen);

	/* init */
	wa.override_redirect = 1;
	wa.background_pixel = BlackPixel(dpy, lock->screen);
	lock->win = XCreateWindow(dpy, lock->root, 0, 0, DisplayWidth(dpy, lock->screen), DisplayHeight(dpy, lock->screen),
			0, DefaultDepth(dpy, lock->screen), CopyFromParent,
			DefaultVisual(dpy, lock->screen), CWOverrideRedirect | CWBackPixel, &wa);
	XAllocNamedColor(dpy, DefaultColormap(dpy, lock->screen), COLOR2, &color, &dummy);
	// XAllocNamedColor(dpy, DefaultColormap(dpy, lock->screen), COLOR1, &color, &dummy);
	lock->colors[1] = color.pixel;
	XAllocNamedColor(dpy, DefaultColormap(dpy, lock->screen), COLOR1, &color, &dummy);
	lock->colors[0] = color.pixel;
	lock->pmap = XCreateBitmapFromData(dpy, lock->win, curs, 8, 8);
	invisible = XCreatePixmapCursor(dpy, lock->pmap, lock->pmap, &color, &color, 0, 0);
	XDefineCursor(dpy, lock->win, invisible);
	XMapRaised(dpy, lock->win);
	for(len = 1000; len; len--) {
		if(XGrabPointer(dpy, lock->root, False, ButtonPressMask | ButtonReleaseMask | PointerMotionMask,
			GrabModeAsync, GrabModeAsync, None, invisible, CurrentTime) == GrabSuccess)
			break;
		usleep(1000);
	}
	if(running && (len > 0)) {
		for(len = 1000; len; len--) {
			if(XGrabKeyboard(dpy, lock->root, True, GrabModeAsync, GrabModeAsync, CurrentTime)
				== GrabSuccess)
				break;
			usleep(1000);
		}
	}

	running &= (len > 0);
	if(!running) {
		unlockscreen(dpy, lock);
		lock = NULL;
	}
	else
		XSelectInput(dpy, lock->root, SubstructureNotifyMask);

	return lock;
}

static void
usage(void) {
	fprintf(stderr, "usage: slock [-v]\n");
	exit(EXIT_FAILURE);
}

static char *
read_pfile(char *name) {
	FILE *f = fopen(name, "r");

	struct stat s;
	if (stat(name, &s) == -1) goto error;

	char *buf = malloc(s.st_size);
	if (buf == NULL) goto error;
	fread(buf, 1, s.st_size, f);
	fclose(f);

	return buf;

error:
		fprintf(stderr, "Could not open: %s.\n", name);
		return NULL;
}

int
main(int argc, char **argv) {
#ifndef HAVE_BSD_AUTH
	const char *pws;
#endif
	Display *dpy;
	int screen;

#ifdef SLOCK_QUIET
	freopen("/dev/null", "a", stdout);
	freopen("/dev/null", "a", stderr);
#endif

	char buf[255] = {0};
	snprintf(buf, sizeof(buf), "%s/.slock_passwd", getenv("HOME"));
	g_pw = read_pfile(buf);

	if((argc > 1) && !strcmp("-n", argv[1])) {
		alt_kill = 0;
	} else if((argc >= 2) && !strcmp("-v", argv[1])) {
		die("slock-%s, © 2006-2012 Anselm R Garbe\n", VERSION);
	} else if(argc != 1) {
		usage();
	}

	if (g_pw) {
		int i = 0;
		while (g_pw[i]) {
			if (g_pw[i] == '\r' || g_pw[i] == '\n') {
				g_pw[i] = '\0';
				break;
			}
			i++;
		}
	}

#ifdef __linux__
	dontkillme();
#endif

	if(!g_pw && !getpwuid(getuid()))
		die("slock: no passwd entry for you\n");

#ifndef HAVE_BSD_AUTH
	pws = getpw();
#endif

	if(!(dpy = XOpenDisplay(0)))
		die("slock: cannot open display\n");
	/* Get the number of screens in display "dpy" and blank them all. */
	nscreens = ScreenCount(dpy);
	locks = malloc(sizeof(Lock *) * nscreens);
	if(locks == NULL)
		die("slock: malloc: %s\n", strerror(errno));
	int nlocks = 0;
	for(screen = 0; screen < nscreens; screen++) {
		if ( (locks[screen] = lockscreen(dpy, screen)) != NULL)
			nlocks++;
	}
	XSync(dpy, False);

	/* Did we actually manage to lock something? */
	if (nlocks == 0) { // nothing to protect
		free(locks);
		XCloseDisplay(dpy);
		return 1;
	}

	/* Everything is now blank. Now wait for the correct password. */
#ifdef HAVE_BSD_AUTH
	readpw(dpy);
#else
	readpw(dpy, pws);
#endif

	/* Password ok, unlock everything and quit. */
	for(screen = 0; screen < nscreens; screen++)
		unlockscreen(dpy, locks[screen]);

	free(locks);
	XCloseDisplay(dpy);

	return 0;
}
