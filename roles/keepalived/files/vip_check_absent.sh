#!/bin/bash

/bin/ip -br addr show | /usr/bin/grep "${1}" > /dev/null 2>&1
result=${?}

# Basically, we're just inverting the result
# fail if found, succeed if not found
if [ ${result} -eq 0 ]; then
  exit 1
elif [ ${result} -eq 1 ]; then
  exit 0
fi

exit ${result}
