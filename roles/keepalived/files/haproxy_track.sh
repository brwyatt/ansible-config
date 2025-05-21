#!/bin/bash

echo "show servers state" | nc localhost 9000 | sed -e 's/^# //' | cut -d' ' -f2,6,8 | tail -n +3 | grep -i "^${1} 2 [^0]" > /dev/null 2>&1
