install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/bin/${PROJECT_NAME} DESTINATION ./bin)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/deploy/${PROJECT_NAME}.service DESTINATION ./systemd)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/README.pdf DESTINATION ./doc)
install(DIRECTORY conf DESTINATION .)
install(DIRECTORY xdp  DESTINATION .)

set(CPACK_PACKAGE_NAME                      "${PROJECT_NAME}")
set(CPACK_PACKAGE_VERSION                   "${PROJECT_PKG_TAG}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY       "connection track base of ebpf/xdp")
set(CPACK_PACKAGE_CONTACT                   "cugriver@163.com")
set(CPACK_PACKAGING_INSTALL_PREFIX          "${CMAKE_INSTALL_PREFIX}")
set(CPACK_SYSTEM_NAME                       "${PROJECT_OS}")
set(CPACK_PACKAGE_FILE_NAME                 "${PROJECT_NAME}-${PROJECT_PKG_TAG}-${PROJECT_ARCH}")

