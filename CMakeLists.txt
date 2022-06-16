cmake_minimum_required(VERSION 3.16)

project(ct)
set(PROJECT_NAME "ct")

set(CMAKE_VERBOSE_MAKEFILE true)

set(CMAKE_INSTALL_PREFIX "/usr/local/ct")

##获取基础数据-commit
execute_process(
    COMMAND sh -c "git rev-parse HEAD | cut -c 1-16"
	OUTPUT_VARIABLE PROJECT_COMMIT
	OUTPUT_STRIP_TRAILING_WHITESPACE
)

##获取基础数据-tag
execute_process(
    COMMAND sh -c "git describe  --tags --abbrev=0 | sed 's/[[:blank:]]//g' | sed 's/^v//g' | awk -F'.' '{printf \"%04x%04x%08x\", $1,$2,$3}'"
	OUTPUT_VARIABLE PROJECT_TAG
	OUTPUT_STRIP_TRAILING_WHITESPACE
)

execute_process(
    COMMAND sh -c "git describe  --tags --abbrev=0 | sed 's/[[:blank:]]//g'"
    COMMAND sh -c "git describe  --tags --abbrev=0 | sed 's/[[:blank:]]//g' | sed 's/^v//g' | awk -F'.' '{printf \"%d.%d.%d-%d\", $1,$2,$3,$4}'"
	OUTPUT_VARIABLE PROJECT_PKG_TAG OUTPUT_STRIP_TRAILING_WHITESPACE
)

##获取基础数据-os
execute_process(
    COMMAND sh -c "uname -s"
	OUTPUT_VARIABLE PROJECT_OS
	OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(TOLOWER ${PROJECT_OS} PROJECT_OS)

execute_process(
    COMMAND sh -c "uname -m"
	OUTPUT_VARIABLE PROJECT_ARCH
	OUTPUT_STRIP_TRAILING_WHITESPACE
)

# 编译二进制文件
execute_process(
    COMMAND sh -c "rm -rf ${CMAKE_CURRENT_SOURCE_DIR}/bin"
    COMMAND sh -c "mkdir -p ${CMAKE_CURRENT_SOURCE_DIR}/bin"
    COMMAND sh -c "CGO_ENABLED=0 GOOS=${PROJECT_OS} GOARCH=amd64 go build -o ${CMAKE_CURRENT_SOURCE_DIR}/bin/${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/cmd/cmd.go"
)

execute_process(
    COMMAND sh -c "rm -rf ${CMAKE_CURRENT_SOURCE_DIR}/xdp"
    COMMAND sh -c "mkdir -p ${CMAKE_CURRENT_SOURCE_DIR}/xdp"
    COMMAND sh -c "clang -g -Wall -O2 -c -target bpf -D__TARGET_ARCH_x86 ${CMAKE_CURRENT_SOURCE_DIR}/bpf/${PROJECT_NAME}.bpf.c -I/usr/include/x86_64-linux-gnu/ -o ${CMAKE_CURRENT_SOURCE_DIR}/xdp/${PROJECT_NAME}.bpf.o"
)

include(${CMAKE_CURRENT_SOURCE_DIR}/deploy/${PROJECT_NAME}.cmake)

if(PROJECT_OS STREQUAL "darwin")
    include(${CMAKE_CURRENT_SOURCE_DIR}/deploy/tgz/tgz.cmake)
elseif(EXISTS "/etc/apt")
    include(${CMAKE_CURRENT_SOURCE_DIR}/deploy/deb/deb.cmake)
elseif(EXISTS "/etc/yum")
    include(${CMAKE_CURRENT_SOURCE_DIR}/deploy/rpm/rpm.cmake)
elseif(EXISTS "/etc/dnf")
    include(${CMAKE_CURRENT_SOURCE_DIR}/deploy/rpm/rpm.cmake)
else()
    message("don't support os")
endif()

include(CPack)
