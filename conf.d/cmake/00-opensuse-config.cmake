message(STATUS "Custom options: 00-opensuse-config.cmake --")
list(APPEND PKG_REQUIRED_LIST uthash)

# Libshell is not part of standard Linux Distro (https://libshell.org/)
set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:/usr/local/lib64/pkgconfig")

# Remember sharelib path to simplify test & debug
set(BINDINGS_LINK_FLAG "-Xlinker -rpath=/usr/local/lib64")

# memfd_create not present even on OpenSuse-15.2
add_definitions(-DMEMFD_CREATE_MISSING)
