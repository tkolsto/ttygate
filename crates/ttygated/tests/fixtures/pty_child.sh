#!/bin/sh

if [ "${1-}" = "ignore-hup" ]; then
    trap '' HUP TERM
fi

sleep 300 &
descendant=$!

printf 'PID:%s\r\n' "$$"
printf 'DESC:%s\r\n' "$descendant"
printf 'ARG1:[%s]\r\n' "${1-}"
printf 'ARG2:[%s]\r\n' "${2-}"
printf 'INITIAL:%s\r\n' "$(stty size)"
printf 'READY\r\n'

if [ "${1-}" = "ignore-hup" ]; then
    while :; do
        sleep 1
    done
fi

while IFS= read -r line; do
    case "$line" in
        exit)
            exit 0
            ;;
        size)
            printf 'RESIZED:%s\r\n' "$(stty size)"
            ;;
        *)
            printf 'ECHO:%s\r\n' "$line"
            ;;
    esac
done
