#!/bin/bash
# Nginx-Healthcheck: Reusable, multi-check health script
# Controlled via CHECKS environment variable (FastCGI)
# Format: TYPE:VALUE;TYPE:VALUE
# Types: port, service, pgrep, custom

STDOUT_DATA=""
EXIT_CODE=0

add_result() {
    local name=$1
    local status=$2
    local message=$3
    [ -n "$STDOUT_DATA" ] && STDOUT_DATA="$STDOUT_DATA,"
    STDOUT_DATA="$STDOUT_DATA\"$name\": {\"status\": \"$status\", \"message\": \"$message\"}"
    [ "$status" == "FAIL" ] && EXIT_CODE=1
}

check_port() {
    local target=$1
    local host="127.0.0.1"
    local port=$target
    
    if [[ "$target" == *":"* ]]; then
        host="${target%%:*}"
        port="${target#*:}"
    fi

    if nc -z -w 2 "$host" "$port" >/dev/null 2>&1; then
        add_result "port_$target" "OK" "Port $port on $host is listening"
    else
        add_result "port_$target" "FAIL" "Port $port on $host is closed"
    fi
}

check_service() {
    local service=$1
    if systemctl is-active --quiet "$service.service"; then
        add_result "service_$service" "OK" "Service is active"
    else
        add_result "service_$service" "FAIL" "Service is not active"
    fi
}

check_pgrep() {
    local pattern=$1
    if pgrep -f "$pattern" >/dev/null; then
        add_result "pgrep_$pattern" "OK" "Process pattern found"
    else
        add_result "pgrep_$pattern" "FAIL" "Process pattern not found"
    fi
}

check_custom() {
    local cmd=$1
    local msg
    msg=$(eval "$cmd" 2>&1)
    if [ $? -eq 0 ]; then
        add_result "custom" "OK" "${msg:-Success}"
    else
        add_result "custom" "FAIL" "${msg:-Failed}"
    fi
}

# Main Execution
if [ -z "$CHECKS" ]; then
    echo "Status: 400 Bad Request"
    echo "Content-Type: application/json"
    echo ""
    echo "{\"error\": \"No CHECKS defined\"}"
    exit 0
fi

IFS=';' read -ra CHECK_ARRAY <<< "$CHECKS"
for i in "${CHECK_ARRAY[@]}"; do
    TYPE="${i%%:*}"
    VALUE="${i#*:}"
    
    case "$TYPE" in
        port)    check_port "$VALUE" ;;
        service) check_service "$VALUE" ;;
        pgrep)   check_pgrep "$VALUE" ;;
        custom)  check_custom "$VALUE" ;;
        *)       add_result "unknown_$TYPE" "FAIL" "Unknown check type" ;;
    esac
done

# Final Response
if [ $EXIT_CODE -eq 0 ]; then
    echo "Status: 200 OK"
else
    echo "Status: 503 Service Unavailable"
fi

echo "Content-Type: application/json"
echo ""
echo "{$STDOUT_DATA}"
exit 0
