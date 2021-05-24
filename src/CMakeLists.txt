###########################################################################
# Copyright 201 IoT.bzh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###########################################################################

# should include static http-client lib before main source
add_subdirectory(oidc-http)
add_subdirectory(idps-builtin)
add_subdirectory(idps-plugins)

# Add target to project dependency list
PROJECT_TARGET_ADD(oidc)

	# compile any C file starting with a lower case
	file(GLOB CSOURCES [a-z]*.c)
	file(GLOB CHEADERS [a-z]*.h)

	# Define project Targets
	add_library(${TARGET_NAME} MODULE ${CSOURCES})

   	target_include_directories(${TARGET_NAME}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/oidc-http ${CMAKE_CURRENT_SOURCE_DIR}/autorities ${PROJECT_SOURCE_DIR}/../fedid-binding/src/fedid-types
    )
    add_dependencies(${TARGET_NAME} afb-http-client idps-builtin)
    target_link_libraries(${TARGET_NAME} afb-http-client idps-builtin)

    target_compile_options(${TARGET_NAME}
        PUBLIC  -Wno-unused-variable
    )

	# Binder exposes a unique public entry point
	SET_TARGET_PROPERTIES(${TARGET_NAME} PROPERTIES
		PREFIX "sec-gate-"
		LABELS "LIBRARY"
        SUFFIX ".extso"
		# LINK_FLAGS "-Wl,--version-script=${PROJECT_SOURCE_DIR}/conf.d/cmake/afb-ext-link.flags"
		IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/sec-gate-${TARGET_NAME}.extso
		OUTPUT_NAME ${TARGET_NAME}
	)

INSTALL(FILES ${CHEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

