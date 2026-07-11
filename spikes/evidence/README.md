# Spike evidence format

Each checked-in summary records:

- the date and host platform;
- relevant tool and dependency versions;
- the reproducible command;
- the expected observation;
- the sanitized actual observation; and
- limitations that separate observed behavior from source-based conclusions.

Raw output is intentionally not retained. A reviewer should be able to rerun
the command and obtain the same semantic result without reusing secrets.
