#依赖的基础镜像
FROM golang:1.22.0 as builder

WORKDIR /home/workspace

#配置go依赖环境
RUN go env -w GO111MODULE=on
RUN go env -w GOPROXY=https://goproxy.cn,direct

#拷贝项目源文件，并取出src路径；相对路径以Dockerfile所在位值为基础
ADD ./ /home/workspace

ENV TZ=Asia/Shanghai

#RUN 执行指定的shell命令；每条RUN命令，当前路径都是以 WORKDIR 为基础
#build scheduler
RUN cd /home/workspace && \
    make build_local && \
    mv build/gossl /home/workspace

#将本地文件拷贝到镜像中
ADD cmd/config.yaml /home/workspace

#对外暴露的端口
EXPOSE 8080

CMD ["/home/workspace/gossl", "-config", "/home/workspace/config/config.yaml"]
