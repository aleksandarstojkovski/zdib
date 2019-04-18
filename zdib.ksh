#!/bin/ksh 

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
        shift
        if [[ -n "$1" ]]; then
          AS_BLOCK_THRESHOLD="$1"
          shift
        fi      
        ;;
      -bn)
        shift
        if [[ -n "$1" ]]; then
          AS_IPSET_BLACKLIST_NAME="$1"
          shift
        fi
        ;;
      -f)
        shift
        if [[ -n "$1" ]]; then
          AS_LOG_FILE="$1"
          shift
        fi
        ;;
      -w)
        shift
        if [[ -n "$1" ]]; then
          AS_WHITELIST_STRING="$1"
          shift
        fi
        ;;              
      -h)
        dis_usage
        ;;
      *)
        dis_usage "Incorrect parameter!"
        ;;
    esac
  done

  if [[ -z "$AS_BLOCK_THRESHOLD" ]]; then
    dis_usage "-bt <BLOCK_THRESHOLD> is mandatory!"
  fi

  if [[ -z "$AS_IPSET_BLACKLIST_NAME" ]]; then
    dis_usage "-bn <BLACKLIST_NAME> is mandatory!"
  fi

  if [[ -z "$AS_LOG_FILE" ]]; then
    dis_usage "-f <FILE> is mandatory!"  
  fi

  if [[ ! -f "$AS_LOG_FILE" ]]; then
    dis_usage "\"$AS_LOG_FILE\" must be a file!"  
  fi

  if [[ ! -r "$AS_LOG_FILE" ]]; then
    dis_usage "\"$AS_LOG_FILE\" must be a readable!"  
  fi

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
    echo "Usage: ./$(basename "$0") -bt <BLOCK_THRESHOLD> -bn <BLACKLIST_NAME> -f <FILE> [ -w <WHITELIST> ]"
    echo
    echo "      -bt threshold of login failures that must be exceeded to block an ip address"
    echo "      -bn name of the ipset blacklist"
    echo "      -w  whitelist (comma separated values)"
    echo "      -f  zimbra log file'"
    echo "      -h  display usage"
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

print_msg "INFO" "Script started"

################################
# setting variables
################################

################################
# precheck
################################

# make sure current user is root 
if [[ $(whoami) != "root" ]]; then
  dis_usage "script must be run as root"
fi

# make sure ipset is installed
command -v ipset >/dev/null 2>&1 || { print_msg "ERROR" "IPSet looks not to be installed"; exit 1; }

# check if blacklist name contains spaces
AS_IS_BLACKLIST_NAME_CONTAINING_SPACES=$(echo "$AS_IPSET_BLACKLIST_NAME" | grep \ | wc -l)
if [[ "$AS_IS_BLACKLIST_NAME_CONTAINING_SPACES" = 1 ]]; then
  print_msg "ERROR" "IPset blacklist name cannot contain spaces"
  exit 1
fi

# check if blacklist name contains spaces
AS_IS_WHITELIS_CONTAINING_SPACES=$(echo "$AS_WHITELIST_STRING" | grep \ | wc -l)
if [[ "$AS_IS_WHITELIS_CONTAINING_SPACES" = 1 ]]; then
  print_msg "ERROR" "Whitelist cannot contain spaces"
  exit 1
fi

# check if blacklist already exist. If not, create it
AS_IS_BLACKLIST_PRESENT=$(ipset list | grep -w "$AS_IPSET_BLACKLIST_NAME")
if [[ -z "$AS_IS_BLACKLIST_PRESENT" ]]; then
  print_msg "INFO" "IPSet blacklist with name \"$AS_IPSET_BLACKLIST_NAME\" does not exist... creating it"
  # blacklist does not exist, let's create it
  ipset create "$AS_IPSET_BLACKLIST_NAME" hash:ip
  # configure iptables to block that ipset blacklist
  iptables -I INPUT -m set --match-set "$AS_IPSET_BLACKLIST_NAME" src -j DROP
fi

###################################
# start to process the file
###################################

IFS=","
AS_WHITELIST_ARRAY=$($AS_WHITELIST_STRING)
unset IFS

###################################
# list of attackers in descending order
###################################

AS_ATTACKER_LIST=$(perl -ne 'print "$1\n" if /.*?oip=(.*?);.*?invalid\s+password/' $AS_LOG_FILE | uniq -c | sort -nr)
if [[ -z "$AS_ATTACKER_LIST" ]]; then
  print_msg "INFO" "No attacker found in log file $AS_LOG_FILE"
  exit 0
fi

IFS=$'\n'
for AS_LINE in $(echo "$AS_ATTACKER_LIST"); do

  AS_LOGIN_FAILURES=$(echo "$AS_LINE" | perl -lane 'print $F[0]')
  AS_ATTACKER_IP=$(echo "$AS_LINE" | perl -lane 'print $F[1]')
  AS_IP_WHITELISTED="FALSE"

  # if login failures are below the block threshold stop
  if [[ "$AS_LOGIN_FAILURES" -lt "$AS_BLOCK_THRESHOLD" ]]; then
    print_msg "INFO" "IP:$AS_ATTACKER_IP is below the threshold. Skipping."
    break
  fi

  if [[ -n "$AS_WHITELIST_STRING" ]]; then
    for AS_WHITELIST_ELEMENT in "${AS_WHITELIST_ARRAY[@]}"; do
      if [[ $AS_ATTACKER_IP == *"$AS_WHITELIST_ELEMENT"* ]]; then
        AS_IP_WHITELISTED="TRUE"
      fi    
    done
  fi

  if [[ $AS_IP_WHITELISTED = "TRUE" ]]; then
    print_msg "INFO" "IP:$AS_ATTACKER_IP is above the threshold, but is whitelisted. Skipping."
  else
    AS_IS_IP_ALREADY_BLACKLISTED=$(ipset list "$AS_IPSET_BLACKLIST_NAME" | grep -w "$AS_ATTACKER_IP")
    if [[ -z "$AS_IS_IP_ALREADY_BLACKLISTED" ]]; then
      print_msg "INFO" "IP:$AS_ATTACKER_IP is above the threshold. Adding to blacklist..."
      ipset add "$AS_IPSET_BLACKLIST_NAME" "$AS_ATTACKER_IP"
    else
      print_msg "INFO" "IP:$AS_ATTACKER_IP is already blacklisted. Skipping. "
    fi
  fi

done

print_msg "INFO" "Finished processing all the IP(s)"
print_msg "INFO" "Script ended"
