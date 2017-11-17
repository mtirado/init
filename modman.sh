#!/bin/sh
# (c) 2017 Michael R. Tirado GPLv3+,
# GNU General Public License, version 3 or any later version.
# TODO transcribe to minimal static C code someday, and don't forget
#      to check for modprobe.blacklist=module kernel parameters
IFS="
	 "
ELEMENTS=""
MODLIST=""
LOADED=""
MODE=""
BLACKLIST="/etc/modblack"
WHITELIST="/etc/modwhite"

exit_usage()
{
	echo ""
	echo "modman [mode: -a, -w, -p, -i(default mode)]"
	echo " -i interactive loading prompt, press l or L key to load each module"
	echo " -a automatically load everything we can that isn't blacklisted"
	echo " -w whitelist at /etc/modwhite is consulted, fail if missing. "
	echo " -p print list of detected modules"
	echo ""
	echo " black/white lists are always consulted if they exist, they work by"
	echo " a simple pattern match per line to tag whole classes of modules "
	echo ""
	echo "example black/white list:"
	echo "--------------------------------------------------------------------"
	echo "lpc_"
	echo "spi_"
	echo "snd_hda"
	echo "-----------------------------EOF------------------------------------"
	echo ""
	exit -1
}



if [ "$1" == "-a" ]; then
	MODE="automatic"
elif [ "$1" == "-w" ]; then
	MODE="whitelist"
elif [ "$1" == "-p" ]; then
	MODE="print"
elif [ "$1" == "-i" ]; then
	MODE="interactive"
elif [ "$1" != "" ]; then
	exit_usage
else
	MODE="interactive"
fi

if [ ! -f "$BLACKLIST" ]; then
	BLACKLIST=""
fi
if [ ! -f "$WHITELIST" ]; then
	# fail if -w mode and the file is missing.
	if [ "$MODE" == "whitelist" ]; then
		echo "whitelist is missing from $WHITELIST"
		exit -1
	fi
	WHITELIST=""
else
	MODE="whitelist"
	echo "using whitelist found at $WHITELIST"
fi

for MODALIAS in $(find /sys -name modalias -exec cat {} \; ); do
	ELEM=$(/sbin/modprobe --show-depends "$MODALIAS" 2>/dev/null)
	if [[ "$ELEM" == insmod* ]]; then
		ELEMENTS+="$ELEM"
	elif [[ "$ELEM" == builtin* ]]; then
		# lines may also start with "builtin"
		ELEMENTS+="$ELEM"
	fi
done

for ELEM in $ELEMENTS; do
	# enumerate  .ko's
	if [[ "$ELEM" != insmod* ]]; then
		if [[ "$ELEM" == *.ko ]]; then
			MODLIST+="$ELEM "
		else
			echo "module missing .ko extension?"
			echo "$ELEM"
		fi
	fi
done

check_whitelist()
{
	if [ "$WHITELIST" != "" ]; then
		while read LINE ;do
			if [[ "$1" = *$LINE* ]]; then
				return 1
			fi
		done < "$WHITELIST"
	fi
	return 0
}

check_blacklist()
{
	if [ "$BLACKLIST" != "" ]; then
		while read LINE ;do
			if [[ "$1" == *$LINE* ]]; then
				return 1
			fi
		done < "$BLACKLIST"
	fi
	return 0
}

load_module()
{
	check_blacklist "$1"
	if [ $? -ne 0 ]; then
		echo "blacklisted $1"
	else
		insmod "$1"
	fi
}

MODLIST=$(echo "$MODLIST")
for MODULE in $MODLIST; do
	if [[ "$LOADED" != *$MODULE* ]]; then
		case "$MODE" in
			automatic)
				load_module "$MODULE"
			;;
			whitelist)
				check_whitelist "$MODULE"
				if [ $? -ne 0 ]; then
					load_module "$MODULE"
				else
					echo "ignoring $MODULE"
				fi
			;;
			interactive)
				echo "(L)oad module: $MODULE ?"
				read -n 1 -s KEY
				if [ "$KEY" != 'l' ] && [ "$KEY" != 'L' ]; then
					echo "skipping module..."
				else
					load_module "$MODULE"
				fi
			;;
			print)
				check_blacklist "$MODULE"
				if [ $? -ne 0 ]; then
					echo "blacklisted: $MODULE"
				else
					echo "load: $MODULE"
				fi
			;;
			*)
				echo "failure."
				exit -1
			;;
		esac
		LOADED+="$MODULE "
	fi
done
