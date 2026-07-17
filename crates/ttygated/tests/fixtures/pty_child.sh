#!/bin/sh

printf 'PID:%s\r\n' "$$"
printf 'ARG1:[%s]\r\n' "${1-}"
printf 'ARG2:[%s]\r\n' "${2-}"
printf 'INITIAL:%s\r\n' "$(stty size)"
printf 'READY\r\n'

while IFS= read -r line; do
    case "$line" in
        size)
            printf 'RESIZED:%s\r\n' "$(stty size)"
            ;;
        *)
            printf 'ECHO:%s\r\n' "$line"
            ;;
    esac
done
