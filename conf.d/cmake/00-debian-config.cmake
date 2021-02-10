message(STATUS "Custom options: 00-debian-config.cmake --")
add_definitions(-DSUSE_LUA_INCDIR)
list(APPEND PKG_REQUIRED_LIST lua53-c++>=5.3)
#list(APPEND PKG_REQUIRED_LIST uthash)

# Libshell is not part of standard Linux Distro (https://libshell.org/)
set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:/usr/local/lib64/pkgconfig")

# Remeber sharelib path to simplify test & debug
set(BINDINGS_LINK_FLAG "-Xlinker -rpath=/usr/lib/x86_64-linux-gnu")