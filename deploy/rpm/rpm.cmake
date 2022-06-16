#https://cmake.org/cmake/help/v3.3/module/CPackRPM.html
#https://rpm-packaging-guide.github.io
set(CPACK_GENERATOR                         "RPM")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE      "${CMAKE_CURRENT_SOURCE_DIR}/deploy/rpm/install")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE     "${CMAKE_CURRENT_SOURCE_DIR}/deploy/rpm/uninstall")
set(CPACK_RPM_SPEC_INSTALL_POST             "/bin/true") # disable strip

