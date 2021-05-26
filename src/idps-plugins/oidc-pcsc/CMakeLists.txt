
PROJECT_TARGET_ADD(pcsc-auth)

	# compile any C file starting with a lower case
	file(GLOB COMMON_SRC pcsc-*.c)
    file(GLOB PLUGIN_SRC oidc-*.c)
	file(GLOB MAIN_SRC   main-*.c)

    # define extra dependencies
    pkg_check_modules (PCSC REQUIRED IMPORTED_TARGET libpcsclite )

	# Define project Targets
    add_library(${TARGET_NAME} MODULE ${COMMON_SRC} ${PLUGIN_SRC})

	target_link_libraries(${TARGET_NAME} PUBLIC PkgConfig::PCSC pthread)

	# pcsc Plugin properties
	SET_TARGET_PROPERTIES(${TARGET_NAME} PROPERTIES
			LABELS "PLUGIN"
			PREFIX "libidp-sgate-"
			SUFFIX ".so"
			OUTPUT_NAME ${TARGET_NAME}
	)

	# compilation include path
	target_include_directories(${TARGET_NAME}
	    PRIVATE ${CMAKE_SOURCE_DIR}/src
    )

PROJECT_TARGET_ADD(pcsc-client)
    add_executable(${TARGET_NAME} ${MAIN_SRC} ${COMMON_SRC})
  	target_link_libraries(${TARGET_NAME} PUBLIC PkgConfig::PCSC libafb.so json-c pthread)

    SET_TARGET_PROPERTIES(${TARGET_NAME} PROPERTIES
	LABELS "EXECUTABLE"
	OUTPUT_NAME ${TARGET_NAME}
    )

