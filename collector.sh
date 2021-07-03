#!/usr/bin/env bash

DIR_PATH=`dirname $0`
FULL_PATH=`readlink --canonicalize $DIR_PATH`

IMAGE_NAME=cybexp-collector

DOCKERFILE_LOC=$FULL_PATH

OG_ARGUMENTS="$@" # in case we need to exec when starting docker

if [ "`id -u`" -eq "0" ]; then
   echo "Not recomended to run ar root. Continuing anyways..."
fi
if [[ "`groups`" == *"docker"* || "`id -u`" -eq "0" ]]; then
      DOCKER="docker"
   else
      DOCKER="sudo docker"

fi

function print_help {
   echo
   echo 'Create and run a docker container of type collector. By default the container is left behind,'
   echo 'vacuum recomended. Build at least once or when code has changed.'
   echo
   echo -e 'Usage:'
   echo -e "  $0"' [Options] config-file'
   echo -e "  $0"' --build --build-only'
   echo -e "  $0"' -a|--get-attrib config-file'
   echo 
   echo -e 'Positional arguments:'
   echo -e '  config-file\t\tconfiguration file yaml'
   echo
   echo -e 'Options arguments:'
   echo -e '  -b, --build\t\tbuild docker image'
   echo -e '  --build-only\t\texit after building'
   echo -e '  -s, --shell\t\trun shell, ignores most flags'


   echo -e '  -c, --vacuum\t\tremove container upon exit. If more than one container'
   echo -e '              \t\tof this type exists, it will remove all'


   echo -e '  -a, --get-attrib\t\tget possible attributes from KMS server.'
   echo -e '                  \t\tThis does not use docker, therefore all other flags are ignored'

   echo -e '  --bind [IFACE:]PORT'
   echo -e '              \t\tinterface and/or port to bind to (eg 192.168.1.100:8080)(default: 6000)'
   echo -e '  -h, --help\t\tprint this help'


   echo 
}

function build_image {
  $DOCKER build -t $IMAGE_NAME $DOCKERFILE_LOC
  return $?
}

function run_image {
   other_args=""
   # if [ $LEFT_INCLUSIVE -eq 1 ]; then
   #    other_args="$other_args --left-inclusive"
   # fi
   # if [ -n "${FROM_TIME+set}" ]; then
   #    other_args="$other_args --from-time $FROM_TIME"
   # fi

   echo "config file: $CONFIG_FILE"
   echo "bind: $BIND_IFACE_PORT"

   # CONT_ID=$($DOCKER run -d -v `realpath $CONFIG_FILE`:/config.yaml -p ${BIND_IFACE_PORT}:8080 -v $FULL_PATH/secrets:/secrets/ -it $IMAGE_NAME $other_args)
   $DOCKER run -v `realpath $CONFIG_FILE`:/config.yaml -p ${BIND_IFACE_PORT}:8080 -v $FULL_PATH/secrets:/secrets/ -it $IMAGE_NAME $other_args
   # $DOCKER logs -f $CONT_ID

   return $?
}
function run_shell {
   touch $OUTPUT_FILE
   $DOCKER run  -v `realpath $CONFIG_FILE`:/config.yaml -p ${BIND_IFACE_PORT}:8080 -v $FULL_PATH/secrets:/secrets/ --entrypoint /bin/bash -it $IMAGE_NAME
   CONT_ID=`$DOCKER ps --all | grep $IMAGE_NAME | awk '{print $1}' | head -n 1`


   return $?

}
function remove_container {
   DOCKER_ID=`$DOCKER ps --all | grep $IMAGE_NAME | awk '{print $1}'`
   echo "Stopping and removing container(s)"
   $DOCKER stop $DOCKER_ID > /dev/null 2>&1
   $DOCKER rm $DOCKER_ID #> /dev/null 2>&1
   return $?
}

# https://stackoverflow.com/a/21189044/12044480
# parse yaml file 
function parse_yaml {
   local prefix=$2
   local s='[[:space:]]*' w='[a-zA-Z0-9_]*' fs=$(echo @|tr @ '\034')
   sed -ne "s|^\($s\):|\1|" \
        -e "s|^\($s\)\($w\)$s:$s[\"']\(.*\)[\"']$s\$|\1$fs\2$fs\3|p" \
        -e "s|^\($s\)\($w\)$s:$s\(.*\)$s\$|\1$fs\2$fs\3|p"  $1 |
   awk -F$fs '{
      indent = length($1)/2;
      vname[indent] = $2;
      for (i in vname) {if (i > indent) {delete vname[i]}}
      if (length($3) > 0) {
         vn=""; for (i=0; i<indent; i++) {vn=(vn)(vname[i])("_")}
         printf("%s%s%s=\"%s\"\n", "'$prefix'",vn, $2, $3);
      }
   }'
}

function get_attrib {
   # echo $CONFIG_FILE
   eval $(parse_yaml $CONFIG_FILE "CONF_")
   auth_args=""
   if [ -n "${CONF_basic_auth_user+set}" ] && [ -n "${CONF_basic_auth_pass+set}" ]; then
      echo "basic auth: enabled"
      auth_args="-u ${CONF_basic_auth_user}:${CONF_basic_auth_pass}"
   else
      echo "basic auth: disabled"
   fi

   curl $auth_args -H "X-Authorization: Bearer ${CONF_kms_access_key}" ${CONF_kms_url}/get/attributes
   exit 0
}


#flags
BUILD_IT=0
BUILD_ONLY=0
SHELL_ONLY=0
CLEANUP=0
BIND_IFACE_PORT="6000"
GET_ATTRIB=0

POSITIONAL=""
while (( "$#" )); do
   case "$1" in
      -h|--help)
         print_help
         exit 0
         ;;
      -b|--build)
         BUILD_IT=1
         shift
         ;;
      --build-only)
         BUILD_ONLY=1
         shift
         ;;
      -s|--shell)
         SHELL_ONLY=1
         shift
         ;;

      -c|--vacuum)
         CLEANUP=1
         shift
         ;;
      -a|--get-attrib)
         GET_ATTRIB=1
         shift
         ;;
      --bind)
         if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
            BIND_IFACE_PORT=$2
            shift 2
         else
            echo "Error: Argument for $1 is missing" >&2
            print_help
            exit 1
         fi
         ;;
      -*|--*=) # unsupported flags
         echo "Error: Unsupported flag $1" >&2
         exit 1
         ;;
      *) # preserve positional arguments
         POSITIONAL="$POSITIONAL $1"
         shift
         ;;
   esac
done
# set positional arguments in their proper place
eval set -- "$POSITIONAL"
if [ "$#" -eq 1 ] && [ $BUILD_ONLY -eq 0 ]; then
   CONFIG_FILE="$1"
   shift 1
elif [ $BUILD_ONLY -eq 0 ];then
   # echo $#
   # echo $POSITIONAL
   echo "Error: Missing positional arguments." >&2
   print_help
   exit 2
fi

if [ $GET_ATTRIB -eq 1 ]; then
   get_attrib
   exit 0
fi

DOCKER_STATE=`systemctl status docker | grep Active: | head -n 1 | awk '{print $2}'`

if [ "$DOCKER_STATE" = "inactive" ]; then
   echo "Starting docker service..."
   sudo systemctl start docker
   exec $0 $OG_ARGUMENTS
fi

if [ $BUILD_IT -eq 1 ]; then
   build_image
   if [ $? -ne 0 ]; then
      echo "Error: Failed to build image" >&2
      exit 3
   fi
fi
if [ $BUILD_ONLY -eq 1 ]; then
   exit 0
fi


if [ "$DOCKER_STATE" = "active" ]; then
   if [ $SHELL_ONLY -eq 1 ]; then
      run_shell
   else
      run_image
   fi

   if [ $CLEANUP -eq 1 ]; then
      remove_container
   fi

else
   echo 'Failed to start docker, please start it.' >&2
   exit 1
fi




