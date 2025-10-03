#!/bin/sh

# Copyright 2021-2025 Rivoreo

# This Source Code Form is subject to the terms of the Mozilla Public License,
# v. 2.0. If a copy of the MPL was not distributed with this file, You can
# obtain one at https://mozilla.org/MPL/2.0/.


if [ $# != 1 ]; then
	printf "Usage: %s <memory-file>\\n" "$0"
	exit 255
fi

MEMORY_FILE="$1"
DISK0_FILE=A
DISK1_FILE=B

[ -n "$I8080ASH_PRINT_REGISTERS_ON_HALT" ] && PRINT_REGISTERS_ON_HALT=1
[ -z "$BASH" ] && [ -n "$I8080ASH_ASSUME_BASH" ] && BASH=assumed
if [ -n "$I8080ASH_USE_BASH_READ" ] && [ -z "$BASH" ]; then
	echo "Warning: I8080ASH_USE_BASH_READ is set, but current shell is not bash" 1>&2
fi

set -e

stdin_status_flags=

set_stdin_nonblock() {
	[ -n "$I8080ASH_ASSUME_NONBLOCK_STDIN" ] && return
	if [ -z "$stdin_status_flags" ]; then
		stdin_status_flags="`perl -e 'use strict; use POSIX; print STDOUT fcntl(STDIN, F_GETFL, 0);'`" || return
		stdin_status_flags="${stdin_status_flags%% *}"
		printf %s\\n "$stdin_status_flags" | grep -Eq '^[0-9]+$' || return
	fi
	perl -e "use strict; use POSIX; fcntl(STDIN, F_SETFL, $stdin_status_flags | O_NONBLOCK);"
}

restore_stdin_status_flags() {
	[ -z "$stdin_status_flags" ] && return
	perl -e "use strict; use POSIX; fcntl(STDIN, F_SETFL, $stdin_status_flags);"
}

# Lookup table for parity, zero and sign flags
# Updates external variable 'PZS'
get_pzs_flags() {
	local i=$1
	set -- \
		0x44 0x00 0x00 0x04 0x00 0x04 0x04 0x00 0x00 0x04 0x04 0x00 0x04 0x00 0x00 0x04 \
		0x00 0x04 0x04 0x00 0x04 0x00 0x00 0x04 0x04 0x00 0x00 0x04 0x00 0x04 0x04 0x00 \
		0x00 0x04 0x04 0x00 0x04 0x00 0x00 0x04 0x04 0x00 0x00 0x04 0x00 0x04 0x04 0x00 \
		0x04 0x00 0x00 0x04 0x00 0x04 0x04 0x00 0x00 0x04 0x04 0x00 0x04 0x00 0x00 0x04 \
		0x00 0x04 0x04 0x00 0x04 0x00 0x00 0x04 0x04 0x00 0x00 0x04 0x00 0x04 0x04 0x00 \
		0x04 0x00 0x00 0x04 0x00 0x04 0x04 0x00 0x00 0x04 0x04 0x00 0x04 0x00 0x00 0x04 \
		0x04 0x00 0x00 0x04 0x00 0x04 0x04 0x00 0x00 0x04 0x04 0x00 0x04 0x00 0x00 0x04 \
		0x00 0x04 0x04 0x00 0x04 0x00 0x00 0x04 0x04 0x00 0x00 0x04 0x00 0x04 0x04 0x00 \
		0x80 0x84 0x84 0x80 0x84 0x80 0x80 0x84 0x84 0x80 0x80 0x84 0x80 0x84 0x84 0x80 \
		0x84 0x80 0x80 0x84 0x80 0x84 0x84 0x80 0x80 0x84 0x84 0x80 0x84 0x80 0x80 0x84 \
		0x84 0x80 0x80 0x84 0x80 0x84 0x84 0x80 0x80 0x84 0x84 0x80 0x84 0x80 0x80 0x84 \
		0x80 0x84 0x84 0x80 0x84 0x80 0x80 0x84 0x84 0x80 0x80 0x84 0x80 0x84 0x84 0x80 \
		0x84 0x80 0x80 0x84 0x80 0x84 0x84 0x80 0x80 0x84 0x84 0x80 0x84 0x80 0x80 0x84 \
		0x80 0x84 0x84 0x80 0x84 0x80 0x80 0x84 0x84 0x80 0x80 0x84 0x80 0x84 0x84 0x80 \
		0x80 0x84 0x84 0x80 0x84 0x80 0x80 0x84 0x84 0x80 0x80 0x84 0x80 0x84 0x84 0x80 \
		0x84 0x80 0x80 0x84 0x80 0x84 0x84 0x80 0x80 0x84 0x84 0x80 0x84 0x80 0x80 0x84
	eval "PZS=\${$((i+1))}"
}

if [ "`printf '' | hexdump -v -e '/1 \"%02x\"' 2> /dev/null`" = 03 ]; then
	read_memory() {
		trap "" INT
		hexdump -v -e '/1 "%u"' -s $1 -n 1 "$MEMORY_FILE"
		trap sigint_handler INT
	}
	byte_to_dec() {
		hexdump -v -e '/1 "%u"'
	}
else
	read_memory_image_in_hex() {
		xxd -c 256 -g 1 -l 65537 "$1" | sed -E -e "s/^[0-9a-f]+: //" -e "s/  .+//"
	}
	read_memory() {
		trap "" INT
		local hex="`xxd -g 1 -s $1 -l 1 \"$MEMORY_FILE\"`"
		trap sigint_handler INT
		hex="${hex#*: }"
		hex="${hex%% *}"
		echo $((0x$hex))
	}
	byte_to_dec() {
		local hex
		hex="`xxd -g 1 -l 1`" && [ -n "$hex" ] || return
		hex="${hex#*: }"
		hex="${hex%% *}"
		echo $((0x$hex))
	}
fi

read_key() {
	if [ -n "$I8080ASH_USE_BASH_READ" ] && [ -n "$BASH" ]; then
		local timeout variable r
		if [ "$1" = --check ]; then
			timeout=0
			variable=variable
		else
			timeout=0.5
			variable=key
			# bash behaves erroneously if a read command is
			# interrupted by a signal and the signal handler runs
			# another read command; workaround this bug by
			# deferring the handling of SIGINT
			got_sigint=
			trap got_sigint=1 INT
		fi
		IFS= read -d "" -r -s -n 1 -t $timeout $variable
		r=$?
		if [ "$1" != --check ]; then
			trap sigint_handler INT
			if [ $r != 0 ]; then
				[ -n "$got_sigint" ] && sigint_handler
				return $r
			fi
			[ "$key" = "
" ] && key=13 || key=`printf %u "'$key"`
		fi
		return $r
	fi
	# Must use dd(1) to limit read size to 1 byte, otherwise hexdump(1) or
	# xxd(1) will read ahead of the size specified by '-n' or '-l',
	# potentially causing key strikes to loss
	local extended_dd_operands=
	[ -n "$I8080ASH_USE_DD_IFLAG_NONBLOCK" ] && extended_dd_operands=iflag=nonblock
	key="`dd bs=1 count=1 $extended_dd_operands 2> /dev/null | byte_to_dec`" || return
	case "$key" in
		"")
			false
			;;
		10)
			key=13
			;;
	esac
}

write_memory() {
	local oct="`printf %03o \"$2\"`"
	trap "" INT
	printf "\\$oct" | dd bs=1 "of=$MEMORY_FILE" conv=notrunc seek=$(($1)) count=1 > /dev/null 2>&1
	#printf "\\$oct" | dd bs=1 seek=$(($1)) count=1 0<&6 > /dev/null 2>&1
	trap sigint_handler INT
}

read_disk() {
	[ $2 -gt 65407 ] && return
	local f
	case $1 in
		0) f="$DISK0_FILE" ;;
		1) f="$DISK1_FILE" ;;
		*) return 1 ;;
	esac
	[ -n "$f" ] || return
	[ -f "$f" ] || return
	trap "" INT
	dd if="$f" ibs=128 skip=$3 of="$MEMORY_FILE" obs=1 seek=$2 count=1 conv=notrunc > /dev/null 2>&1
	trap sigint_handler INT
}

write_disk() {
	local f
	case $1 in
		0) f="$DISK0_FILE" ;;
		1) f="$DISK1_FILE" ;;
		*) return 1 ;;
	esac
	[ -n "$f" ] || return
	trap "" INT
	dd if="$MEMORY_FILE" ibs=1 skip=$2 of="$f" obs=128 seek=$3 count=128 conv=notrunc > /dev/null 2>&1
	trap sigint_handler INT
}

print_registers() {
	if [ "$1" = --raw ]; then
		printf "A=0x%02x B=0x%02x C=0x%02x D=0x%02x E=0x%02x H=0x%02x L=0x%02x SP=0x%04x PC=0x%04x FLAGS=0x%02x\\n" $A $B $C $D $E $H $L $SP $PC $FLAGS 1>&2
	else
		printf "A=0x%02x B=0x%02x C=0x%02x D=0x%02x E=0x%02x H=0x%02x L=0x%02x SP=0x%04x PC=0x%04x CARRY=%s PARITY=%s AUXCARRY=%s ZERO=%s SIGN=%s\\n" $A $B $C $D $E $H $L $SP $PC $((FLAGS&1)) $((!!(FLAGS&(1<<2)))) $((!!(FLAGS&(1<<4)))) $((!!(FLAGS&(1<<6)))) $((!!(FLAGS&(1<<7)))) 1>&2
	fi
}

sigint_handler() {
	local answer
	restore_stdin_status_flags
	cat 1>&2 << EOT
Ctrl-C pressed, select an action:
 1. Pass ^C into emulator as keyboard input.
 2. Print register values.
 3. Print register values and terminate emulator.
 4. Terminate emulator.
EOT
	while true; do
		if [ -n "$I8080ASH_USE_BASH_READ" ] && [ -n "$BASH" ]; then
			read -n 1 -p "> " answer
		else
			printf "> " 1>&2
			#answer="`dd bs=1 count=1 2> /dev/null`" || exit
			answer="`perl -e 'my \$b; my \$s = sysread STDIN, \$b, 1; exit 1 if \$s < 1; print STDOUT \$b;'`"
		fi || exit
		printf %s\\n "$answer" 1>&2
		case "$answer" in
			1)
				key=3
				break
				;;
			2)
				print_registers
				break
				;;
			3)
				print_registers
				exit 0
				;;
			4)
				exit 0
				;;
			*)
				echo "Invalid answer, please try again" 1>&2
				;;
		esac
	done
	[ -z "$BASH" ] || [ -z "$I8080ASH_USE_BASH_READ" ] && set_stdin_nonblock
}

echo "i8080 emulator for Almquist shell"
echo "Copyright 2021-2025 Rivoreo"

for register in A B C D E H L SP PC FLAGS; do
	eval "v=\"\$$register\""
	[ -n "$v" ] && v=$((v)) && [ "$v" -ge 0 ] && [ "$v" -lt $((${#register}>1?65536:256)) ] || v=0
	eval "$register=\$v"
done
unset register v

i=0
for flag in CARRY "" PARITY "" AUXCARRY "" ZERO SIGN; do
	if [ -n "$flag" ] && eval "v=\"\$$flag\"" && [ -n "$v" ]; then
		[ $((v)) -gt 0 ] && FLAGS=$((FLAGS|(1<<i))) || FLAGS=$((FLAGS&~(1<<i)&65535))
	fi
	i=$((i+1))
done
unset i flag v

# Pending input key
key=

set +e

echo
if { [ -z "$BASH" ] || [ -z "$I8080ASH_USE_BASH_READ" ]; } && ! set_stdin_nonblock; then
	echo "Failed to make stdin non-blocking" 1>&2
	exit 1
fi
if [ -t 0 ]; then
	if [ -n "$I8080ASH_USE_STTY_MIN" ]; then
		trap "restore_stdin_status_flags; stty icanon echo sane" EXIT
		stty -icanon -echo min 1
	else
		trap "restore_stdin_status_flags; stty icanon echo" EXIT
		stty -icanon -echo
	fi
else
	trap restore_stdin_status_flags EXIT
fi
trap "print_registers; exit" HUP
trap sigint_handler INT

do_call() {
	local new_pc=$((`read_memory $PC`|(`read_memory $(((PC+1)&65535))`<<8)))
	local ret_addr=$(((PC+2)&65535))
	SP=$((SP-1&65535)); write_memory $SP $((ret_addr>>8))
	SP=$((SP-1&65535)); write_memory $SP $((ret_addr&255))
	PC=$new_pc
}

do_ret() {
	PC=$((`read_memory $SP`|(`read_memory $(((SP+1)&65535))`<<8)))
	SP=$((SP+2))
}

while true; do
	opcode=`read_memory $PC`
	PC=$((PC+1))
	case $opcode in
		0) # NOP
			;;

		64) # MOV B,B
			;;
		65) # MOV B,C
			B=$C
			;;
		66) # MOV B,D
			B=$D
			;;
		67) # MOV B,E
			B=$E
			;;
		68) # MOV B,H
			B=$H
			;;
		69) # MOV B,L
			B=$L
			;;
		70) # MOV B,M
			B=`read_memory $((H<<8|L))`
			;;
		71) # MOV B,A
			B=$A
			;;

		72) # MOV C,B
			C=$B
			;;
		73) # MOV C,C
			;;
		74) # MOV C,D
			C=$D
			;;
		75) # MOV C,E
			C=$E
			;;
		76) # MOV C,H
			C=$H
			;;
		77) # MOV C,L
			C=$L
			;;
		78) # MOV C,M
			C=`read_memory $((H<<8|L))`
			;;
		79) # MOV C,A
			C=$A
			;;

		80) # MOV D,B
			D=$B
			;;
		81) # MOV D,C
			D=$C
			;;
		82) # MOV D,D
			;;
		83) # MOV D,E
			D=$E
			;;
		84) # MOV D,H
			D=$H
			;;
		85) # MOV D,L
			D=$L
			;;
		86) # MOV D,M
			D=`read_memory $((H<<8|L))`
			;;
		87) # MOV D,A
			D=$A
			;;

		88) # MOV E,B
			E=$B
			;;
		89) # MOV E,C
			E=$C
			;;
		90) # MOV E,D
			E=$D
			;;
		91) # MOV E,E
			;;
		92) # MOV E,H
			E=$H
			;;
		93) # MOV E,L
			E=$L
			;;
		94) # MOV E,M
			E=`read_memory $((H<<8|L))`
			;;
		95) # MOV E,A
			E=$A
			;;

		96) # MOV H,B
			H=$B
			;;
		97) # MOV H,C
			H=$C
			;;
		98) # MOV H,D
			H=$D
			;;
		99) # MOV H,E
			H=$E
			;;
		100) # MOV H,H
			;;
		101) # MOV H,L
			H=$L
			;;
		102) # MOV H,M
			H=`read_memory $((H<<8|L))`
			;;
		103) # MOV H,A
			H=$A
			;;

		104) # MOV L,B
			L=$B
			;;
		105) # MOV L,C
			L=$C
			;;
		106) # MOV L,D
			L=$D
			;;
		107) # MOV L,E
			L=$E
			;;
		108) # MOV L,H
			L=$H
			;;
		109) # MOV L,L
			;;
		110) # MOV L,M
			L=`read_memory $((H<<8|L))`
			;;
		111) # MOV L,A
			L=$A
			;;

		112) # MOV M,B
			write_memory $((H<<8|L)) $B
			;;
		113) # MOV M,C
			write_memory $((H<<8|L)) $C
			;;
		114) # MOV M,D
			write_memory $((H<<8|L)) $D
			;;
		115) # MOV M,E
			write_memory $((H<<8|L)) $E
			;;
		116) # MOV M,H
			write_memory $((H<<8|L)) $H
			;;
		117) # MOV M,L
			write_memory $((H<<8|L)) $L
			;;

		118) # HLT
			[ -n "$PRINT_REGISTERS_ON_HALT" ] && print_registers
			break
			;;

		119) # MOV M,A
			write_memory $((H<<8|L)) $A
			;;

		120) # MOV A,B
			A=$B
			;;
		121) # MOV A,C
			A=$C
			;;
		122) # MOV A,D
			A=$D
			;;
		123) # MOV A,E
			A=$E
			;;
		124) # MOV A,H
			A=$H
			;;
		125) # MOV A,L
			A=$L
			;;
		126) # MOV A,M
			A=`read_memory $((H<<8|L))`
			;;
		127) # MOV A,A
			;;

		# MVI instructions (Move Immediate)
		6) # MVI B,nn
			B=`read_memory $PC`
			PC=$((PC+1))
			;;
		14) # MVI C,nn
			C=`read_memory $PC`
			PC=$((PC+1))
			;;
		22) # MVI D,nn
			D=`read_memory $PC`
			PC=$((PC+1))
			;;
		30) # MVI E,nn
			E=`read_memory $PC`
			PC=$((PC+1))
			;;
		38) # MVI H,nn
			H=`read_memory $PC`
			PC=$((PC+1))
			;;
		46) # MVI L,nn
			L=`read_memory $PC`
			PC=$((PC+1))
			;;
		54) # MVI M,nn
			write_memory $((H<<8|L)) `read_memory $PC`
			PC=$((PC+1))
			;;
		62) # MVI A,nn
			A=`read_memory $PC`
			PC=$((PC+1))
			;;

		# LXI instructions (Load immediate 16-bit)
		1) # LXI B,nnnn
			C=`read_memory $PC`
			PC=$(((PC+1)&65535))
			B=`read_memory $PC`
			PC=$((PC+1))
			;;
		17) # LXI D,nnnn
			E=`read_memory $PC`
			PC=$(((PC+1)&65535))
			D=`read_memory $PC`
			PC=$((PC+1))
			;;
		33) # LXI H,nnnn
			L=`read_memory $PC`
			PC=$(((PC+1)&65535))
			H=`read_memory $PC`
			PC=$((PC+1))
			;;
		49) # LXI SP,nnnn
			_Z=`read_memory $PC`
			PC=$(((PC+1)&65535))
			_Y=`read_memory $PC`
			PC=$((PC+1))
			SP=$((_Z|(_Y<<8)))
			;;

		128) # ADD B
			_R=$((A+B))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		129) # ADD C
			_R=$((A+C))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		130) # ADD D
			_R=$((A+D))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		131) # ADD E
			_R=$((A+E))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		132) # ADD H
			_R=$((A+H))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		133) # ADD L
			_R=$((A+L))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		134) # ADD M
			_R=$((A+`read_memory $((H<<8|L))`))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		135) # ADD A
			_R=$((A+A))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;

		136) # ADC B
			_R=$((A+B+(FLAGS&1)))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		137) # ADC C
			_R=$((A+C+(FLAGS&1)))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		138) # ADC D
			_R=$((A+D+(FLAGS&1)))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		139) # ADC E
			_R=$((A+E+(FLAGS&1)))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		140) # ADC H
			_R=$((A+H+(FLAGS&1)))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		141) # ADC L
			_R=$((A+L+(FLAGS&1)))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		142) # ADC M
			_R=$((A+`read_memory $((H<<8|L))`+(FLAGS&1)))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		143) # ADC A
			_R=$((A+A+(FLAGS&1)))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;

		144) # SUB B
			_R=$((A-B))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		145) # SUB C
			_R=$((A-C))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		146) # SUB D
			_R=$((A-D))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		147) # SUB E
			_R=$((A-E))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		148) # SUB H
			_R=$((A-H))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		149) # SUB L
			_R=$((A-L))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		150) # SUB M
			_R=$((A-`read_memory $((H<<8|L))`))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		151) # SUB A
			_R=$((A-A))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;

		152) # SBB B
			_R=$((A-B-(FLAGS&1)))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		153) # SBB C
			_R=$((A-C-(FLAGS&1)))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		154) # SBB D
			_R=$((A-D-(FLAGS&1)))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		155) # SBB E
			_R=$((A-E-(FLAGS&1)))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		156) # SBB H
			_R=$((A-H-(FLAGS&1)))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		157) # SBB L
			_R=$((A-L-(FLAGS&1)))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		158) # SBB M
			_R=$((A-`read_memory $((H<<8|L))`-(FLAGS&1)))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		159) # SBB A
			_R=$((A-A-(FLAGS&1)))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;

		198) # ADI nn
			_R=$((A+`read_memory $PC`))
			PC=$((PC+1))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		206) # ACI nn
			_R=$((A+`read_memory $PC`+(FLAGS&1)))
			PC=$((PC+1))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		214) # SUI nn
			_R=$((A-`read_memory $PC`))
			PC=$((PC+1))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;
		222) # SBI nn
			_R=$((A-`read_memory $PC`-(FLAGS&1)))
			PC=$((PC+1))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			A=$((_R&255))
			;;

		160) # ANA B
			A=$((A&B))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		161) # ANA C
			A=$((A&C))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		162) # ANA D
			A=$((A&D))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		163) # ANA E
			A=$((A&E))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		164) # ANA H
			A=$((A&H))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		165) # ANA L
			A=$((A&L))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		166) # ANA M
			A=$((A&`read_memory $((H<<8|L))`))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		167) # ANA A
			get_pzs_flags $A
			FLAGS=$PZS
			;;

		168) # XRA B
			A=$((A^B))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		169) # XRA C
			A=$((A^C))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		170) # XRA D
			A=$((A^D))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		171) # XRA E
			A=$((A^E))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		172) # XRA H
			A=$((A^H))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		173) # XRA L
			A=$((A^L))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		174) # XRA M
			A=$((A^`read_memory $((H<<8|L))`))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		175) # XRA A
			A=0
			get_pzs_flags $A
			FLAGS=$PZS
			;;

		176) # ORA B
			A=$((A|B))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		177) # ORA C
			A=$((A|C))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		178) # ORA D
			A=$((A|D))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		179) # ORA E
			A=$((A|E))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		180) # ORA H
			A=$((A|H))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		181) # ORA L
			A=$((A|L))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		182) # ORA M
			A=$((A|`read_memory $((H<<8|L))`))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		183) # ORA A
			get_pzs_flags $A
			FLAGS=$PZS
			;;

		184) # CMP B
			_R=$((A-B))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			;;
		185) # CMP C
			_R=$((A-C))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			;;
		186) # CMP D
			_R=$((A-D))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			;;
		187) # CMP E
			_R=$((A-E))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			;;
		188) # CMP H
			_R=$((A-H))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			;;
		189) # CMP L
			_R=$((A-L))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			;;
		190) # CMP M
			_R=$((A-`read_memory $((H<<8|L))`))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			;;
		191) # CMP A
			_R=$((A-A))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			;;

		# Immediate logical instructions
		230) # ANI nn
			A=$((A&`read_memory $PC`))
			PC=$((PC+1))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		238) # XRI nn
			A=$((A^`read_memory $PC`))
			PC=$((PC+1))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		246) # ORI nn
			A=$((A|`read_memory $PC`))
			PC=$((PC+1))
			get_pzs_flags $A
			FLAGS=$PZS
			;;
		254) # CPI nn
			_R=$((A-`read_memory $PC`))
			PC=$((PC+1))
			get_pzs_flags $((_R&255))
			FLAGS=$(((_R>>8&1)|PZS|(_R>>4&16)))
			;;

		204) # CZ nnnn (Call if Zero)
			if [ $((FLAGS&64)) != 0 ]; then
				do_call
			else
				PC=$((PC+2))
			fi
			;;
		212) # CNC nnnn (Call if No Carry)
			if [ $((FLAGS&1)) = 0 ]; then
				do_call
			else
				PC=$((PC+2))
			fi
			;;
		220) # CC nnnn (Call if Carry)
			if [ $((FLAGS&1)) != 0 ]; then
				do_call
			else
				PC=$((PC+2))
			fi
			;;
		228) # CPO nnnn (Call if Parity Odd)
			if [ $((FLAGS&4)) = 0 ]; then
				do_call
			else
				PC=$((PC+2))
			fi
			;;
		236) # CPE nnnn (Call if Parity Even)
			if [ $((FLAGS&4)) != 0 ]; then
				do_call
			else
				PC=$((PC+2))
			fi
			;;
		244) # CP nnnn (Call if Plus)
			if [ $((FLAGS&128)) = 0 ]; then
				do_call
			else
				PC=$((PC+2))
			fi
			;;
		252) # CM nnnn (Call if Minus)
			if [ $((FLAGS&128)) != 0 ]; then
				do_call
			else
				PC=$((PC+2))
			fi
			;;
		196) # CNZ nnnn (Call if Not Zero)
			if [ $((FLAGS&64)) = 0 ]; then
				do_call
			else
				PC=$((PC+2))
			fi
			;;
		195) # JMP nnnn
			_Z=`read_memory $PC`; PC=$(((PC+1)&65535))
			_Y=`read_memory $PC`; PC=$((PC+1))
			PC=$((_Z|(_Y<<8)))
			;;
		194) # JNZ nnnn
			_Z=`read_memory $PC`; PC=$(((PC+1)&65535))
			_Y=`read_memory $PC`; PC=$((PC+1))
			[ $((FLAGS&64)) = 0 ] && PC=$((_Z|(_Y<<8)))
			;;
		202) # JZ nnnn
			_Z=`read_memory $PC`; PC=$(((PC+1)&65535))
			_Y=`read_memory $PC`; PC=$((PC+1))
			[ $((FLAGS&64)) != 0 ] && PC=$((_Z|(_Y<<8)))
			;;
		210) # JNC nnnn
			_Z=`read_memory $PC`; PC=$(((PC+1)&65535))
			_Y=`read_memory $PC`; PC=$((PC+1))
			[ $((FLAGS&1)) = 0 ] && PC=$((_Z|(_Y<<8)))
			;;
		218) # JC nnnn
			_Z=`read_memory $PC`; PC=$(((PC+1)&65535))
			_Y=`read_memory $PC`; PC=$((PC+1))
			[ $((FLAGS&1)) != 0 ] && PC=$((_Z|(_Y<<8)))
			;;
		226) # JPO nnnn
			_Z=`read_memory $PC`; PC=$(((PC+1)&65535))
			_Y=`read_memory $PC`; PC=$((PC+1))
			[ $((FLAGS&4)) = 0 ] && PC=$((_Z|(_Y<<8)))
			;;
		234) # JPE nnnn
			_Z=`read_memory $PC`; PC=$(((PC+1)&65535))
			_Y=`read_memory $PC`; PC=$((PC+1))
			[ $((FLAGS&4)) != 0 ] && PC=$((_Z|(_Y<<8)))
			;;
		242) # JP nnnn
			_Z=`read_memory $PC`; PC=$(((PC+1)&65535))
			_Y=`read_memory $PC`; PC=$((PC+1))
			[ $((FLAGS&128)) = 0 ] && PC=$((_Z|(_Y<<8)))
			;;
		250) # JM nnnn
			_Z=`read_memory $PC`; PC=$(((PC+1)&65535))
			_Y=`read_memory $PC`; PC=$((PC+1))
			[ $((FLAGS&128)) != 0 ] && PC=$((_Z|(_Y<<8)))
			;;

		201) # RET
			do_ret
			;;
		192) # RNZ
			[ $((FLAGS&64)) = 0 ] && do_ret
			;;
		200) # RZ
			[ $((FLAGS&64)) != 0 ] && do_ret
			;;
		208) # RNC
			[ $((FLAGS&1)) = 0 ] && do_ret
			;;
		216) # RC
			[ $((FLAGS&1)) != 0 ] && do_ret
			;;
		224) # RPO
			[ $((FLAGS&4)) = 0 ] && do_ret
			;;
		232) # RPE
			[ $((FLAGS&4)) != 0 ] && do_ret
			;;
		240) # RP
			[ $((FLAGS&128)) = 0 ] && do_ret
			;;
		248) # RM
			[ $((FLAGS&128)) != 0 ] && do_ret
			;;

		205|221|237|253) # CALL nnnn
			_Z=`read_memory $PC`; PC=$(((PC+1)&65535))
			_Y=`read_memory $PC`; PC=$(((PC+1)&65535))
			write_memory $(((SP+65535)&65535)) $((PC>>8))
			write_memory $(((SP+65534)&65535)) $((PC&255))
			if [ $opcode = 237 ] && [ $_Z = 237 ] && [ $_Y -gt 1 ]; then
				_Z=`read_memory 64508`
				[ $_Y = 2 ] && _Y=read_disk || _Y=write_disk
				$_Y $((`read_memory 64511`-1)) $((`read_memory 64506`|(`read_memory 64507`<<8))) $((_Z|(((`read_memory 64510`<<8)|`read_memory 64509`)<<7))) && A=0 || A=1
			else
				PC=$((_Z|(_Y<<8)))
				SP=$((SP-2))
			fi
			;;

		197) # PUSH B
			SP=$((SP-1&65535))
			write_memory $SP $B
			SP=$((SP-1&65535))
			write_memory $SP $C
			;;
		213) # PUSH D
			SP=$((SP-1&65535))
			write_memory $SP $D
			SP=$((SP-1&65535))
			write_memory $SP $E
			;;
		229) # PUSH H
			SP=$((SP-1&65535))
			write_memory $SP $H
			SP=$((SP-1&65535))
			write_memory $SP $L
			;;
		245) # PUSH PSW
			SP=$((SP-1&65535))
			write_memory $SP $A
			SP=$((SP-1&65535))
			write_memory $SP $(((FLAGS&0xd7)|2))
			;;

		193) # POP B
			C=`read_memory $SP`
			SP=$(((SP+1)&65535))
			B=`read_memory $SP`
			SP=$((SP+1))
			;;
		209) # POP D
			E=`read_memory $SP`
			SP=$(((SP+1)&65535))
			D=`read_memory $SP`
			SP=$((SP+1))
			;;
		225) # POP H
			L=`read_memory $SP`
			SP=$(((SP+1)&65535))
			H=`read_memory $SP`
			SP=$((SP+1))
			;;
		241) # POP PSW
			FLAGS=$((`read_memory $SP`&0xd5))
			SP=$(((SP+1)&65535))
			A=`read_memory $SP`
			SP=$((SP+1))
			;;

		4) # INR B
			B=$((B+1&255))
			get_pzs_flags $B
			FLAGS=$(((FLAGS&1)|PZS|(((B^(B-1))>>4)&16)))
			;;
		12) # INR C
			C=$((C+1&255))
			get_pzs_flags $C
			FLAGS=$(((FLAGS&1)|PZS|(((C^(C-1))>>4)&16)))
			;;
		20) # INR D
			D=$((D+1&255))
			get_pzs_flags $D
			FLAGS=$(((FLAGS&1)|PZS|(((D^(D-1))>>4)&16)))
			;;
		28) # INR E
			E=$((E+1&255))
			get_pzs_flags $E
			FLAGS=$(((FLAGS&1)|PZS|(((E^(E-1))>>4)&16)))
			;;
		36) # INR H
			H=$((H+1&255))
			get_pzs_flags $H
			FLAGS=$(((FLAGS&1)|PZS|(((H^(H-1))>>4)&16)))
			;;
		44) # INR L
			L=$((L+1&255))
			get_pzs_flags $L
			FLAGS=$(((FLAGS&1)|PZS|(((L^(L-1))>>4)&16)))
			;;
		52) # INR M
			_addr=$((H<<8|L))
			_temp=$((`read_memory $_addr`+1&255))
			write_memory $_addr $_temp
			get_pzs_flags $_temp
			FLAGS=$(((FLAGS&1)|PZS|(((_temp^(_temp-1))>>4)&16)))
			;;
		60) # INR A
			A=$((A+1&255))
			get_pzs_flags $A
			FLAGS=$(((FLAGS&1)|PZS|(((A^(A-1))>>4)&16)))
			;;

		5) # DCR B
			B=$((B-1&255))
			get_pzs_flags $B
			FLAGS=$(((FLAGS&1)|PZS|(((B^(B+1))>>4)&16)))
			;;
		13) # DCR C
			C=$((C-1&255))
			get_pzs_flags $C
			FLAGS=$(((FLAGS&1)|PZS|(((C^(C+1))>>4)&16)))
			;;
		21) # DCR D
			D=$((D-1&255))
			get_pzs_flags $D
			FLAGS=$(((FLAGS&1)|PZS|(((D^(D+1))>>4)&16)))
			;;
		29) # DCR E
			E=$((E-1&255))
			get_pzs_flags $E
			FLAGS=$(((FLAGS&1)|PZS|(((E^(E+1))>>4)&16)))
			;;
		37) # DCR H
			H=$((H-1&255))
			get_pzs_flags $H
			FLAGS=$(((FLAGS&1)|PZS|(((H^(H+1))>>4)&16)))
			;;
		45) # DCR L
			L=$((L-1&255))
			get_pzs_flags $L
			FLAGS=$(((FLAGS&1)|PZS|(((L^(L+1))>>4)&16)))
			;;
		53) # DCR M
			_addr=$((H<<8|L))
			_temp=$((`read_memory $_addr`-1&255))
			write_memory $_addr $_temp
			get_pzs_flags $_temp
			FLAGS=$(((FLAGS&1)|PZS|(((_temp^(_temp+1))>>4)&16)))
			;;
		61) # DCR A
			A=$((A-1&255))
			get_pzs_flags $A
			FLAGS=$(((FLAGS&1)|PZS|(((A^(A+1))>>4)&16)))
			;;

		# INX/DCX instructions (16-bit increment/decrement)
		3) # INX B
			C=$((C+1&255))
			[ $C = 0 ] && B=$((B+1&255))
			;;
		19) # INX D
			E=$((E+1&255))
			[ $E = 0 ] && D=$((D+1&255))
			;;
		35) # INX H
			L=$((L+1&255))
			[ $L = 0 ] && H=$((H+1&255))
			;;
		51) # INX SP
			SP=$((SP+1&65535))
			;;
		11) # DCX B
			C=$((C-1&255))
			[ $C = 255 ] && B=$((B-1&255))
			;;
		27) # DCX D
			E=$((E-1&255))
			[ $E = 255 ] && D=$((D-1&255))
			;;
		43) # DCX H
			L=$((L-1&255))
			[ $L = 255 ] && H=$((H-1&255))
			;;
		59) # DCX SP
			SP=$((SP-1&65535))
			;;

		2) # STAX B
			write_memory $((B<<8|C)) $A
			;;
		18) # STAX D
			write_memory $((D<<8|E)) $A
			;;
		10) # LDAX B
			A=`read_memory $((B<<8|C))`
			;;
		26) # LDAX D
			A=`read_memory $((D<<8|E))`
			;;
		42) # LHLD nnnn
			_Z=`read_memory $PC`; PC=$(((PC+1)&65535))
			_Y=`read_memory $PC`; PC=$((PC+1))
			_addr=$((_Z|(_Y<<8)))
			L=`read_memory $_addr`
			H=`read_memory $((_addr+1))`
			;;
		34) # SHLD nnnn
			_Z=`read_memory $PC`; PC=$(((PC+1)&65535))
			_Y=`read_memory $PC`; PC=$((PC+1))
			_addr=$((_Z|(_Y<<8)))
			write_memory $_addr $L
			write_memory $((_addr+1)) $H
			;;
		58) # LDA nnnn
			_Z=`read_memory $PC`; PC=$(((PC+1)&65535))
			_Y=`read_memory $PC`; PC=$((PC+1))
			A=`read_memory $((_Z|(_Y<<8)))`
			;;
		50) # STA nnnn
			_Z=`read_memory $PC`; PC=$(((PC+1)&65535))
			_Y=`read_memory $PC`; PC=$((PC+1))
			write_memory $((_Z|(_Y<<8))) $A
			;;
		9) # DAD B
			_HL=$((H<<8|L))
			_BC=$((B<<8|C))
			_R=$((_HL+_BC))
			H=$((_R>>8&255))
			L=$((_R&255))
			FLAGS=$(((FLAGS&0xfe)|(_R>>16&1)))
			;;
		25) # DAD D
			_HL=$((H<<8|L))
			_DE=$((D<<8|E))
			_R=$((_HL+_DE))
			H=$((_R>>8&255))
			L=$((_R&255))
			FLAGS=$(((FLAGS&0xfe)|(_R>>16&1)))
			;;
		41) # DAD H
			_HL=$((H<<8|L))
			_R=$((_HL+_HL))
			H=$((_R>>8&255))
			L=$((_R&255))
			FLAGS=$(((FLAGS&0xfe)|(_R>>16&1)))
			;;
		57) # DAD SP
			_HL=$((H<<8|L))
			_R=$((_HL+SP))
			H=$((_R>>8&255))
			L=$((_R&255))
			FLAGS=$(((FLAGS&0xfe)|(_R>>16&1)))
			;;
		7) # RLC
			_bit=$((A>>7))
			A=$(((A<<1|_bit)&255))
			FLAGS=$(((FLAGS&0xfe)|_bit))
			;;
		15) # RRC
			_bit=$((A&1))
			A=$(((A>>1)|(_bit<<7)))
			FLAGS=$(((FLAGS&0xfe)|_bit))
			;;
		23) # RAL
			_temp=$A
			A=$(((A<<1|(FLAGS&1))&255))
			FLAGS=$(((FLAGS&0xfe)|(_temp>>7)))
			;;
		31) # RAR
			_temp=$A
			A=$((A>>1|(FLAGS&1)<<7))
			FLAGS=$(((FLAGS&0xfe)|(_temp&1)))
			;;
		39) # DAA
			_carry=$((FLAGS&1))
			[ $((A&15)) -gt 9 ] || [ $((FLAGS&16)) != 0 ] && A=$((A+6))
			[ $A -gt 159 ] || [ $_carry != 0 ] && A=$((A+96)) && _carry=1
			A=$((A&255))
			get_pzs_flags $A
			FLAGS=$(((_carry)|PZS|((A^(A-1))>>4&16)))
			;;
		47) # CMA
			A=$((A^255))
			;;
		55) # STC
			FLAGS=$((FLAGS|1))
			;;
		63) # CMC
			FLAGS=$((FLAGS^1))
			;;
		233) # PCHL
			PC=$((H<<8|L))
			;;
		249) # SPHL
			SP=$((H<<8|L))
			;;
		235) # XCHG
			_temp=$D
			D=$H
			H=$_temp
			_temp=$E
			E=$L
			L=$_temp
			;;
		227) # XTHL
			_temp=$L
			L=`read_memory $SP`
			write_memory $SP $_temp
			_temp=$H
			H=`read_memory $((SP+1))`
			write_memory $((SP+1)) $_temp
			;;

		243) # DI
			;;
		251) # EI
			;;

		211) # OUT nn
			case `read_memory $PC` in
				0|2)
					printf "\\`printf %03o $A`"
					;;
			esac
			PC=$((PC+1))
			;;
		219) # IN nn
			case `read_memory $PC` in
				0)
					if [ -n "$key" ] || read_key --check; then
						A=255
					else
						A=0
					fi
					;;
				1)
					if [ -n "$key" ] || read_key; then
						A=$key
						key=
					else
						A=0
					fi
					;;
				2)
					#printf 'PC = 0x%04x\n' $PC 1>&2
					A=0
					;;
			esac
			PC=$((PC+1))
			;;

		199) # RST 0
			SP=$((SP-1&65535)); write_memory $SP $((PC>>8))
			SP=$((SP-1&65535)); write_memory $SP $((PC&255))
			PC=0
			;;
		207) # RST 1
			SP=$((SP-1&65535)); write_memory $SP $((PC>>8))
			SP=$((SP-1&65535)); write_memory $SP $((PC&255))
			PC=8
			;;
		215) # RST 2
			SP=$((SP-1&65535)); write_memory $SP $((PC>>8))
			SP=$((SP-1&65535)); write_memory $SP $((PC&255))
			PC=16
			;;
		223) # RST 3
			SP=$((SP-1&65535)); write_memory $SP $((PC>>8))
			SP=$((SP-1&65535)); write_memory $SP $((PC&255))
			PC=24
			;;
		231) # RST 4
			SP=$((SP-1&65535)); write_memory $SP $((PC>>8))
			SP=$((SP-1&65535)); write_memory $SP $((PC&255))
			PC=32
			;;
		239) # RST 5
			SP=$((SP-1&65535)); write_memory $SP $((PC>>8))
			SP=$((SP-1&65535)); write_memory $SP $((PC&255))
			PC=40
			;;
		247) # RST 6
			SP=$((SP-1&65535)); write_memory $SP $((PC>>8))
			SP=$((SP-1&65535)); write_memory $SP $((PC&255))
			PC=48
			;;
		255) # RST 7
			SP=$((SP-1&65535)); write_memory $SP $((PC>>8))
			SP=$((SP-1&65535)); write_memory $SP $((PC&255))
			PC=56
			;;

		*)
			printf "Unimplemented opcode 0x%02x\\n" $opcode 1>&2
			;;
	esac
	PC=$((PC&65535))
	SP=$((SP&65535))
done
