#!/bin/sh
if [ "$DISPLAY" = "" ]; then
	export DISPLAY=:1
fi
sleep 4
fluxbox &
sleep 1
xrdb -load ~/.Xresources
