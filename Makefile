GOPATH		:= $(shell go env GOPATH)
GOPATH1		:= $(firstword $(subst :, ,$(GOPATH)))
export GOPATH
GO111MODULE	:= on
export GO111MODULE
UNAME		:= $(shell uname)
SRCPATH     := $(shell pwd)

default: build

# build our fork of libsodium, placing artifacts into crypto/lib/ and crypto/include/
build:
	cd $(SRCPATH)/crypto/libsodium-fork && \
		./autogen.sh && \
		./configure --disable-shared --prefix="$(SRCPATH)/crypto/" && \
		$(MAKE) && \
		$(MAKE) install
