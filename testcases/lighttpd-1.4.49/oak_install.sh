# Change SConstruct file for optimization level
scons -c
scons -j 4 build_static=1 build_dynamic=0 >scons.out
#cp ./sconsbuild/static/build/lighttpd oak/lighttpd-Os

# To run, sudo ./sconsbuild/static/build/lighttpd -f ./oak/lighttpd.conf
