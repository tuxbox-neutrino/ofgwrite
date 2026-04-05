# ofgwrite

ofgwrite from Betacentauri, based on mtd-utils-native-1.5.1 and busybox 1.24.1.

This fork is maintained by tuxbox-neutrino.
Focus: robust, reproducible, branding-free flash integration for
Tuxbox/Neutrino targets.

Upstream base: https://github.com/oe-alliance/ofgwrite

## Usage

`ofgwrite <parameter> <image_directory>`

Options:
- `-k --kernel` flash kernel (default)
- `-r --rootfs` flash rootfs (default)
- `-n --nowrite` detect image and target devices without writing
- `-h --help` show help

## Safety

Run once with `-n` and verify device detection before any real write.
If detection is wrong, do not flash.

## Fork Policy

- Keep upstream history and attribution intact.
- Keep runtime output and behavior branding-free.
- Carry technical changes for stability, compatibility, and safety.
- Pin integration in build layers by fixed `SRCREV`.
