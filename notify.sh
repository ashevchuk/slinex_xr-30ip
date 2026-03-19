#!/bin/sh

#./slinex_ctrl.pl -h 10.100.100.164 -p 20510 -u Admin -w 123 -h al044a1123 notify
./slinex_ctrl.pl -h 10.100.100.164 -p 20510 -u Admin -w 123 -h al044a1123 -e 'notify-send "Door" "Visitor"' notify
