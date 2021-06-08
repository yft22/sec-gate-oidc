file(REMOVE_RECURSE
  "afb-sgate-oidc-debug-test.wgt"
  "afb-sgate-oidc-debug.wgt"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/populate.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
