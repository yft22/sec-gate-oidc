
PROJECT_TARGET_ADD(pam-auth)

	# compile any C file starting with a lower case
	file(GLOB CSOURCES [a-z]*.c)

	# Define project Targets
	find_library (PAM_DEVEL libpam required)
	add_library(${TARGET_NAME} MODULE ${CSOURCES})
	target_link_libraries(${TARGET_NAME} pam)

	# Alsa Plugin properties
	SET_TARGET_PROPERTIES(${TARGET_NAME} PROPERTIES
			LABELS "PLUGIN"
			PREFIX ""
			SUFFIX ".idpso"
			OUTPUT_NAME ${TARGET_NAME}
	)

	# compilation include path
	target_include_directories(${TARGET_NAME}
	    PRIVATE ${CMAKE_SOURCE_DIR}/src
		PRIVATE ${CMAKE_SOURCE_DIR}/src/oidc-http
    )