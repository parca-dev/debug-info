![Build](https://github.com/parca-dev/debug-info/actions/workflows/build.yml/badge.svg)
![Container](https://github.com/parca-dev/debug-info/actions/workflows/container.yml/badge.svg)
[![Apache 2 License](https://img.shields.io/badge/license-Apache%202-blue.svg)](LICENSE)

# debug-info
A command line utility to handle tasks regarding debug information (extraction, upload and debugging)

## Configuration

Flags:

[embedmd]:# (dist/help.txt)
```txt
Usage: debug-info <command>

Flags:
  -h, --help                Show context-sensitive help.
      --log-level="info"    Log level.

Commands:
  upload --store-address=STRING <path> ...
    Upload debug information files.

  extract <path> ...
    Extract debug information.

  buildid <path>
    Extract buildid.

Run "debug-info <command> --help" for more information on a command.
```
