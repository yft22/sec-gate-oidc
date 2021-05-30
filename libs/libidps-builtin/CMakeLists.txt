PROJECT_TARGET_ADD(idps-builtin)

	# compile any C file starting with a lower case
	file(GLOB CSOURCES [a-z]*.c)

	# Define project Targets
	add_library(${TARGET_NAME} STATIC ${CSOURCES})
    add_dependencies(${TARGET_NAME} curl-glue-afb sgate-oidc)
    target_link_libraries(${TARGET_NAME} curl-glue-afb sgate-oidc)

	# oidc Plugin properties
	SET_TARGET_PROPERTIES(${TARGET_NAME} PROPERTIES
		OUTPUT_NAME ${TARGET_NAME}
	)

	# compilation include path
	target_include_directories(${TARGET_NAME}
	    INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
	    PRIVATE ${CMAKE_SOURCE_DIR}/src
    )
