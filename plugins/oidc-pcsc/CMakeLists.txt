
PROJECT_TARGET_ADD(pcscd-auth)

	# compile any C file starting with a lower case
	file(GLOB CSOURCES [a-z]*.c)

	# Define project Targets
	add_library(${TARGET_NAME} MODULE ${CSOURCES})

    add_dependencies(${TARGET_NAME} pcscd-glue sgate-oidc)
	target_link_libraries(${TARGET_NAME} pcscd-glue sgate-oidc)

	# Pam Plugin properties
	SET_TARGET_PROPERTIES(${TARGET_NAME} PROPERTIES
			LABELS "PLUGIN"
			PREFIX "libidp-sgate-"
			SUFFIX ".so"
			OUTPUT_NAME ${TARGET_NAME}
	)