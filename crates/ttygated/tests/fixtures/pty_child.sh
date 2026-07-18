#!/bin/sh

if [ "${1-}" = "ignore-hup" ]; then
    trap '' HUP TERM
fi

if [ "${1-}" = "natural-resistant" ]; then
    trap '' HUP
fi
if [ "${1-}" = "natural-resistant" ]; then
    if [ "${3-}" = "record-hup-exit-23" ]; then
        hup_marker=${2-}
    else
        hup_marker=
    fi
    (
        trap 'if [ -n "$hup_marker" ]; then printf "HUP\n" > "$hup_marker"; fi' HUP
        while :; do
            sleep 1
        done
    ) &
else
    sleep 300 &
fi
descendant=$!
if [ "${1-}" = "browser-track" ]; then
    printf '%s %s\n' "$$" "$descendant" >> "${2:?browser PID marker required}"
fi
if [ "${1-}" = "natural-resistant" ]; then
    trap - HUP
fi

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

if [ "${1-}" = "flood" ]; then
    while :; do
        printf 'flood-output\r\n'
    done
fi

if [ "${1-}" = "flood-count" ]; then
    payload=$(printf '%04096d' 0)
    count=0
    while :; do
        printf '%s\r\n' "$payload"
        count=$((count + 1))
        printf '%s\n' "$count" > "${2:?progress path required}"
    done
fi

while IFS= read -r line; do
    case "$line" in
        exit)
            if [ "${1-}" = "natural-resistant" ] && [ "${3-}" = "record-hup-exit-23" ]; then
                exit 23
            fi
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
