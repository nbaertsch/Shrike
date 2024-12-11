# Package

version       = "0.1.0"
author        = "nbaertsch"
description   = "Hunting for and injecting RWX 'mockingjay' DLLs in pure nim."
license       = "MIT"
srcDir        = "src"
binDir        = "bin"
bin           = @["Shrike"]


# Dependencies

requires "nim >= 1.6.14"
requires "winim >= 3.9.2"
requires "termstyle"
requires "suru >= 0.3.1"
requires "regex >= 0.21.0"
requires "nimprotect"
