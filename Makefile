VERSION=v1.0.0
BRANCH=v1.0.0
OS := $(shell uname -s)
PLATFORM=$(shell uname -m)
ARCH := $(shell uname -m)
DATETIME=$(shell date "+%Y/%m/%d %H:%M:%S")
GIT_BRANCH = $(shell git rev-parse --abbrev-ref HEAD)
GIT_COMMIT = $(shell git log --pretty=format:'%h' -n 1)
# 注意：这里的路径是你自己的交叉编译工具链的路径, 下载地址https://github.com/messense/homebrew-macos-cross-toolchains/releases
CROSS_BUILD_LINUX_GUN_GCC = /Users/hxy/wkdir/x86_64-unknown-linux-gnu/build/x86_64-unknown-linux-gnu-gcc

LOCALCONF_HOME=github.com/warm3snow/gossl/config
GOLDFLAGS += -X "${LOCALCONF_HOME}.CurrentVersion=${VERSION}"
GOLDFLAGS += -X "${LOCALCONF_HOME}.BuildDateTime=${DATETIME}"
GOLDFLAGS += -X "${LOCALCONF_HOME}.GitBranch=${GIT_BRANCH}"
GOLDFLAGS += -X "${LOCALCONF_HOME}.GitCommit=${GIT_COMMIT}"

# 本地编译
build:
	go mod tidy && go build -mod=mod -ldflags '${GOLDFLAGS}' -o ./build/gossl ./cmd/main.go

# 本地编译 depend on vendor
build_local:
	go build -ldflags '${GOLDFLAGS}' -o ./build/gossl ./cmd/main.go

build_docker:
	# build binary
	go mod tidy && go mod vendor
	# build docker image
	./docker_build.sh -t v1.0.0 -p false
# 本地需要安装交叉编译器
build_linux:
	# mkdir build
	@rm -rf build/linux_amd64 && mkdir -p build/linux_amd64
	# linux
	go mod tidy && CGO_ENABLED=1 CC=${CROSS_BUILD_LINUX_GUN_GCC}  GOARCH=amd64 GOOS=linux go build  -ldflags '${GOLDFLAGS}' -o ./build/gossl ./cmd/main.go

	md5 ./build/gossl | awk '{print $NF}' > build/md5.txt
# 生成代码(no use)
generate:
	go generate ./...
# 单元测试
ut:
	go test ./...
