# slock - a fork of the suckless screenlocker for the _extremely_ paranoid

This is my personal fork of slock. It is the only screenlocker secure enough
for me to use.

## Changes from the original Slock

- Custom Password: You can provide a custom password so you don't have to enter
  your user password on the X server. Simply create a ~/.slock_passwd file with
  your separate password in it.

- Alarms: A siren will play if a user enters an incorrect password. It must
  reside in ~/slock.

- Automatic Shutdown: Your machine will immediately shutdown if:

  1. The wrong password is entered more than 5 times.

  2. ALT/CTRL/F1-F13 is pressed to switch VTs or to try to kill the X server.
     Also, if ALT+SYSRQ is attempted to be used.

  - Automatic shutdown requires a sudoers option to be set in /etc/sudoers:

    - systemd: `[username] [hostname] =NOPASSWD: /usr/bin/systemctl poweroff`
    - sysvinit: `[username] [hostname] =NOPASSWD: /usr/bin/shutdown -h now`

    You must change [username] and [hostname] to your username and the hostname
    of the machine.

    NOTE: It is wise to combine this feature with a bios password as well as an
    encrypted home+swap partition. Once your machine is powered off. Your data
    is no longer accessible in any manner.

- GRSecurity BadUSB Prevention: If you have GRSecurity patched onto and enabled
  in your kernel, when slock is started, all new USB devices will be disabled.
  This requires that the kernel.grsecurity.grsec_lock sysctl option be set to 0,
  which is a security risk to an attacker with local access. If you enable
  STRICT\_USBOFF when slock comes on, kernel.grsecurity.grsec_lock will be set
  to 1 and new USB devices will denied until you reboot.

  You will need to have this line in your /etc/sysctl.d/grsec.conf

        kernel.grsecurity.grsec_lock = 0

  and it also requires the same permissions as Automatic Shutdown in
  /etc/sudoers.

- Webcam Support (requires ffmpeg): This will take a webcam shot of whoever may
  be tampering with your machine before poweroff.

- Twilio Support: You will receive an SMS to your phone when someone inputs a
  wrong password or pressed ALT/CTRL/F1-13/SYSRQ. See twilio_example.h to create a
  twilio.h file. You will need a twilio account to set this up.

  These SMS's can optionally be MMS's containing a webcam shot of whoever is
  potentially tampering with your machine.

- Disabling alt+sysrq and ctrl+alt+backspace before shutting down: This
  prevents an attacker from killing the screenlock quickly before the shutdown.

  - This requires a sudoers option to be set in /etc/sudoers:

    - `[username] [hostname] =NOPASSWD: /usr/bin/tee /proc/sys/kernel/sysrq`

    You must change [username] and [hostname] to your username and the hostname
    of the machine.

- Transparent Lock Screen

  - The lock screen is now an ARGB window. The screen will dim on lock (or turn
    black with no compositor).

## Requirements

In order to build slock you need the Xlib header files.

- Potential runtime deps: sudo, ffmpeg, setxkbmap, curl, aplay
- Other potential requirements: a twilio account, an imgur account

## Installation

Edit config.mk to match your local setup (slock is installed into
the /usr/local namespace by default).

Afterwards enter the following command to build and install slock
(if necessary as root):

``` bash
$ make clean install
```

## Running slock

Simply invoke the 'slock' command. To get out of it, enter your password.
