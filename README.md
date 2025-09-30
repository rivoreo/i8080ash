# i8080 emulator for Almquist shell

A complete Intel 8080 processor emulator with emulated UART console and disk I/O, implemented in pure Almquist shell (ash) script. This particular emulated machine is compatible with [the 8080 emulator written by Oscar Toledo G. for the 19th IOCCC (2006)](https://www.ioccc.org/2006/toledo2/index.html).

## Variants

2 variants of the emulator are available:
* `i8080.ash` loads the specified program into memory, where the memory is implemented by 65536 individual shell variables
* `i8080-rw.ash` directly reads and updates the specified memory file in-place; one example usecase is to use `/dev/fb0` as memory; because every memory access runs an external **hexdump(1)** or **dd(1)** command, memory performance will be poor.

## Supported shells

Any POSIX-compatible Almquist shell is supported, this excludes ancient pre-POSIX versions of Almquist shell.

GNU bash 2.0 or later is also supported, but a reduced performance is expected.

It may work with other Unix shells, but this is not guaranteed.

Primarily tested with the Almquist shell provided by FreeBSD (`/bin/sh`) and Debian (`/bin/dash`).

dash versions 0.5.7 and later, and busybox ash are known to have suboptimal performance.

## Other dependencies

In addition to a supported shell, some other basic external commands are required by the emulator:

* **dd(1)**
* **hexdump(1)** or **xxd(1)**
* **sed(1)**, if **xxd(1)** is being used
* **grep(1)**
* **perl(1)**
* **stty(1)**, if using from a terminal (the usual case)

## Supporting files

* `c_basic.bin` is a memory image providing Tiny BASIC, a BASIC interpretor; this file is identical to <https://www.ioccc.org/2006/toledo2/C.BASIC>.
* `c_bios.bin` is a memory image providing the CP/M BIOS, for booting CP/M; this file is identical to <https://www.ioccc.org/2006/toledo2/C.BIOS>.
* `A` and `B` are disk images for 2 emulated disks, not provided here; in order to boot CP/M, you need to prepare these 2 files:
	* Download <http://www.retroarchive.org/cpm/os/KAYPROII.ZIP>;
	* Extract `SOURCE/CPM64.COM` file from `KAYPROII.ZIP` (For example `7za x KAYPROII.ZIP SOURCE/CPM64.COM`);
	* Copy the extracted `SOURCE/CPM64.COM` to `A` and `B`.

## Usage

Both variants accept a single path name to the memory image file. Because `i8080-rw.ash` updates the memory image file in-place, it is recommended to first duplicate the memory image file, when trying out this variant.

If environment variables `A`, `B`, `C`, `D`, `E`, `H`, `L`, `SP`, `PC` and `FLAGS` are set to appropriate values, they will used for as the initial values of the respective registers to start emulation; this can be used to restore a previously interrupted emulation.

When running the emulator, pressing Ctrl-C will giving a menu for different actions. If you choose to dump registers and terminate emulation, you will be able to restore this emulation state by setting the register values in environment variables, as described above.

### Examples

```sh
sh i8080.ash c_bios.bin
```

```sh
cat c_bios.bin > /dev/fb0
sh i8080-rw.ash /dev/fb0
```

```sh
A=0 B=0 C=255 D=77 E=255 H=238 L=212 SP=61245 PC=64277 FLAGS=84 sh i8080.ash my-last-save
```

## Transfer files into virtual disk image

This emulator did not implement the file import support as available in Toledo's emulator. You will have to use Toledo's emulator for this task, if needed.

You may follow the instructions on <https://www.ioccc.org/2006/toledo2/index.html> or <https://web.archive.org/web/20120112040347/http://nanochess.110mb.com/emulator.html> to transfer files into your virtual disk images.

## History

The initial work of this project was began in 2021, as improvements to the **i8080 emulater in bash** that written by NASZVADI Peter. The improvements I made include bug fixes for existing instructions, implementation of new instructions, and disk I/O support, to enable the emulator to correctly run CP/M, as well as Zork I for CP/M; other added features include significantly faster loading of user-specified memory image file, advanced Ctrl-C handling including memory dump support, ability to save and restore of emulation state, and an alternative variant for direct memory file access (for playing with `/dev/fb0`).

I was excited to demonstrate this version at the time; the result is this video on YouTube, [Zork, CP/M running on BASH, with /dev/fb0 as memory](https://www.youtube.com/watch?v=7MO9w6h6Hwo).

However, there a serious issue with the original program by NASZVADI Peter; it did not came with a license, to enable 3rd-party distribution permission for the program! Unfortunately the original author [refused to license it](https://github.com/retrohun/blog/issues/4), so sadly the program remains proprietary to this day.

The solution? Rewrite the entire emulation logic from scratch! This move also provided a bonus that I was able to target the program to Almquist shell instead of bash; this creates a significant performance advantage over the old proprietary implementation, if an efficient implementation of Almquist shell is used, such as FreeBSD ash or dash 0.5.5.1.

## License

Source files `i8080.ash` and `i8080-rw.ash` are distributed under the Mozilla Public License, version 2.0; a copy of this license is provided as `COPYING` file.

Binary files `c_basic.bin` and `c_bios.bin` are distributed under Creative Commons Attribution-ShareAlike 4.0 International license.
