--threads:off
--app:console
--define:mingw
--opt:size
--gc:orc
--o:bin

if defined arch64:
    --cpu:amd64

elif defined arch32:
    --cpu:i386
    --passC : "-m32"
    --passL : "-m32"
