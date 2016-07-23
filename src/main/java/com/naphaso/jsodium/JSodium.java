package com.naphaso.jsodium;

/**
 * Created by wolong on 21/07/16.
 */
public class JSodium {
    static {
        System.load("/Users/wolong/dev/naphaso.com/jsodium/src/main/java/libjsodium.dylib");
        Sodium.sodium_init();
    }


}
