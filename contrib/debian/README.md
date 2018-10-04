
Debian
====================
This directory contains files used to package klksd/klks-qt
for Debian-based Linux systems. If you compile klksd/klks-qt yourself, there are some useful files here.

## klks: URI support ##


klks-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install klks-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your klksqt binary to `/usr/bin`
and the `../../share/pixmaps/klks128.png` to `/usr/share/pixmaps`

klks-qt.protocol (KDE)

