#!/bin/sh
if [ "$DISPLAY" = "" ]; then
	export DISPLAY=:1
fi
Xorg -config ~/sporg.conf -logfile "sporg.log$DISPLAY" $DISPLAY &
sleep 5
fluxbox &
sleep 2
xrdb -load ~/.Xresources

