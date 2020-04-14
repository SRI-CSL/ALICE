#PKG_CONFIG="pkg-config --static" ./configure --disable-shared --enable-static --with-libssh2 > config.out>&1
#LDFLAGS="-static" PKG_CONFIG="pkg-config --static" ./configure --disable-shared --enable-static --with-libssh2 > config.out>&1
LDFLAGS="-static" PKG_CONFIG="pkg-config --static" ./configure --disable-shared --enable-static --with-libssh2 --without-ssl --enable-debug > config.out>&1
#LDFLAGS="-static" ./configure --disable-shared --enable-static --with-libssh2 --with-ssl > config.out>&1
#./configure --with-libssh2 > config.out>&1
#make V=1 curl_LDFLAGS="-all-static" CFLAGS="-Werror-implicit-function-declaration -O0 -Wno-system-headers -pthread" > make.out 2>&1
make V=1 curl_LDFLAGS="-Wl,--gc-sections" CFLAGS="-Werror-implicit-function-declaration -O2 -Wno-system-headers -pthread -g" > make.out 2>&1

# gcc -Werror-implicit-function-declaration -O2 -Wno-system-headers -pthread -s -Wl,--gc-sections -o curl curl-slist_wc.o curl-tool_binmode.o curl-tool_bname.o curl-tool_cb_dbg.o curl-tool_cb_hdr.o curl-tool_cb_prg.o curl-tool_cb_rea.o curl-tool_cb_see.o curl-tool_cb_wrt.o curl-tool_cfgable.o curl-tool_convert.o curl-tool_dirhie.o curl-tool_doswin.o curl-tool_easysrc.o curl-tool_formparse.o curl-tool_getparam.o curl-tool_getpass.o curl-tool_help.o curl-tool_helpers.o curl-tool_homedir.o curl-tool_hugehelp.o curl-tool_libinfo.o curl-tool_main.o curl-tool_metalink.o curl-tool_msgs.o curl-tool_operate.o curl-tool_operhlp.o curl-tool_panykey.o curl-tool_paramhlp.o curl-tool_parsecfg.o curl-tool_strdup.o curl-tool_setopt.o curl-tool_sleep.o curl-tool_urlglob.o curl-tool_util.o curl-tool_vms.o curl-tool_writeout.o curl-tool_xattr.o ../lib/curl-strtoofft.o ../lib/curl-nonblock.o ../lib/curl-warnless.o  ../lib/.libs/libcurl.a /home/osboxes/oak/code/patch/sha256/sha256_lib.o -lssh2 -lgcrypt /usr/lib/x86_64-linux-gnu/libgpg-error.so -lz -pthread

cp ./src/curl ./src/curl-Os
#make V=1 curl_LDFLAGS="-Wl,--gc-sections -Wl,-Bstatic -lcrypto -Wl,-Bdynamic -lgcc" CFLAGS="-Werror-implicit-function-declaration -O2 -Wno-system-headers -pthread -g" > make.out 2>&1
#make V=1 CFLAGS="-Werror-implicit-function-declaration -O2 -Wno-system-headers -pthread -g" > make.out 2>&1

