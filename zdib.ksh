#!/bin/bash 

######################################################################
# Script Name      : zdib.ksh                                                                                         
# Description      : Zimbra dynamic ip blocker                                                                                                                                                                      
# Author       	   : Aleksandar Stojkovski                                              
# Email            : aleksandar@stojkovski.ch                                          
######################################################################

######################################################################
# functions
######################################################################

################################
# function get_parameters
################################

function get_arguments {

  while [[ $# -gt 0 ]]; do
    case $1 in
      -bt)

        ;;
      -bn)

        ;;
      -f)

        ;;
      -w)

        ;;              
      -h)
        dis_usage
        ;;
      *)
        dis_usage "Incorrect parameter!"
        ;;
    esac
  done

}

################################
# function dis_usage
################################

function dis_usage {

    if [[ -n $1 ]]; then
        echo
        echo "Error: $1"
    fi

    echo
    echo "Usage: ./$(basename "$0") -t <BLOCK_THRESHOLD> -bn <BLACKLIST_NAME> -f <FILE> [ -w <WHITELIST> ]"
    echo
    echo "      -bt threshold of login failures that must be exceeded to block an ip address"
    echo "      -bn name of the ipset blacklist"
    echo "      -w  whitelist (comma separated values)"
    echo "      -f  zimbra log file "
    echo

    exit 1

}

################################
# function print_msg
################################

function print_msg {

    print "$(date '+[%d.%m.%Y %H:%M:%S]') $1 : $(basename "$0") : $2"

}

######################################################################
# MAIN
######################################################################

get_arguments "$@"

################################
# setting variables
################################

################################
# precheck
################################

# check current user is zimbra technical user 
if [[ $(whoami) != "zimbra" ]]; then
    dis_usage "script must be run as root"
fi

###################################
# start to process the file
###################################
