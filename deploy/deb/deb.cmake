#https://gitlab.kitware.com/cmake/community/-/wikis/doc/cpack/PackageGenerators
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "cugriver@163.com")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_SOURCE_DIR}/deploy/deb/postinst;${CMAKE_CURRENT_SOURCE_DIR}/deploy/deb/prerm;")

##安装编排脚本
#   名称        阶段          说明              流程
# preinst     解压前执行  用于升级或安装   成功后执行postinst
# postinst    安装过程
# prerm       卸载前执行
# postrm      卸载
