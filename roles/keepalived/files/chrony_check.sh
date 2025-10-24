#!/bin/bash

/usr/bin/chronyc tracking | /usr/bin/grep -E '^Leap status\s+:\s+Normal$'

exit $?
