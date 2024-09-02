#!/bin/bash

show_help() {
    echo "Usage: $0 -t <tag> [-p <true|false>] [-r <registry_address>]"
    echo "Options:"
    echo "  -t <tag>                Specify the tag for Docker images."
    echo "  -p <true|false>         Push the Docker images to the registry. (Default: false)"
    echo "  -r <registry_address>   Specify the address of the Docker registry."
    echo "                          If not provided, Docker Hub is assumed as the default registry."
}

# Check if the number of parameters is correct
if [ $# -lt 1 ]; then
    show_help
    exit 1
fi

# Default values
push_flag=false

# Parse command line options
while getopts ":t::p:r:" opt; do
    case ${opt} in
        t)
            docker_tag=$OPTARG
            ;;
        p)
            push_flag=$OPTARG
            if [[ ! $OPTARG =~ ^(true|false)$ ]]; then
                echo "Invalid argument for -p. Please provide 'true' or 'false'." >&2
                show_help
                exit 1
            fi
            ;;
        r)
            registry_address=$OPTARG
            ;;
        \?)
            echo "Invalid option: $OPTARG" 1>&2
            show_help
            exit 1
            ;;
        :)
            echo "Option -$OPTARG requires an argument." 1>&2
            show_help
            exit 1
            ;;
    esac
done

shift $((OPTIND -1))

# Check if tag is provided
if [ -z "$docker_tag" ]; then
    echo "Tag not specified."
    show_help
    exit 1
fi

echo "Building gossl environment image"

#git pull && docker build -f ./Dockerfile-build -t warm3snow/gossl:${docker_tag} .
docker build -f ./Dockerfile -t warm3snow/gossl:${docker_tag} .

if [ ! -z "$registry_address" ]; then
  #tag gossl-build
    docker tag warm3snow/gossl:${docker_tag} ${registry_address}/warm3snow/gossl:${docker_tag}
fi

#是否push
if [ "$push_flag" == "true" ]; then
  # 假设$docker_register_address 为空，则默认为docker hub
  if [ -z "$registry_address" ]; then
    docker push warm3snow/gossl:${docker_tag}
  else
    docker push ${registry_address}/warm3snow/gossl:${docker_tag}
  fi
fi