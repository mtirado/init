#!/bin/sh
if [ "$DISPLAY" = "" ]; then
	export DISPLAY=:1
fi
sleep 1
Xorg -config ~/sporg.conf -logfile "sporg.log$DISPLAY" $DISPLAY &
