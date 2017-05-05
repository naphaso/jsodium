#!/bin/sh

gcc -v -c -I../libsodium/src/libsodium/include -I$JAVA_HOME/include/ -I$JAVA_HOME/include/darwin/ main.c
gcc -v -dynamiclib -o ../src/main/resources/libjsodium.dylib main.o \
    lib/libsodium.a \
    lib/libaesni.a \
    lib/libavx2.a \
    lib/libsodium.a \
    lib/libsse2.a \
    lib/libsse41.a \
    lib/libssse3.a

