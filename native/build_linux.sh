#!/bin/sh
export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
gcc -fPIC -shared -I../libsodium/src/libsodium/include -I$JAVA_HOME/include/ -I$JAVA_HOME/include/linux/ -o ../src/main/resources/libjsodium.so main.c \
    linux/libsodium.a \
    linux/libaesni.a \
    linux/libavx2.a \
    linux/libsse2.a \
    linux/libsse41.a \
    linux/libssse3.a

