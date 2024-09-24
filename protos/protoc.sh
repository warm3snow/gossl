#!/bin/sh

 protoc --go_out=. --go-grpc_out=. ./gossl.proto