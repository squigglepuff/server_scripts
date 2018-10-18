#!/bin/bash

# First, clear the terminal and reset the cursor to 0,0!
printf "\e[2J";
printf "\e[0;0H";

# See if the user doesn't want columns!
NOCOL=0;
if [[ "$1" == "--nocol" ]]; then
    NOCOL=1;
fi

# First, print the CPU details.
printf "\e[1;31m= CPU Details =\e[0m\n";
printf "\e[31mModel:\e[0m %s\n" $(grep '^vendor_id.*' /proc/cpuinfo | head -n 1 | cut -d : -f2 | sed 's/ //g');
printf "\e[31mFamily:\e[0m %s\n" $(grep '^model\ name.*' /proc/cpuinfo | head -n 1 | cut -d : -f2 | sed 's/ //g');
printf "\e[31mNumber Processors:\e[0m %d\n" $(nproc);
printf "\e[31mSpeed (MHz):\e[0m %s\n" $(grep '^cpu\ MHz.*' /proc/cpuinfo | head -n 1 | cut -d : -f2 | sed 's/ //g');
printf "\e[31mLoad:\e[0m ";
w | head -n 1 | sed 's/.* load average: \(.*\)$/\1/';

# Memory info next.
printf "\n\e[1;32m= RAM Details =\e[0m\n";
free && vmstat;

printf "\n\e[1;33m= Disk IO Details =\e[0m\n";
printf "\e[33mNumber Disks:\e[0m %d\n" $(lsblk -r 2>&1 | grep -i '^\(s\|v\)d[a-z]\ .*' | grep -v SWAP | wc -l);
printf "\e[33mNumber Parts:\e[0m %d\n" $(lsblk -r 2>&1 | grep -i '^\(s\|v\)d[a-z][0-9]\ .*' | grep -v SWAP | wc -l);
printf "\e[33mI/O Statistics:\e[0m\n";
iostat -x

printf "\n\e[1;34m= Networking Details =\e[0m\n";
printf "\e[34mNumber Interfaces:\e[0m %d\n" $(ifconfig | grep -i '^e\(th\|np\).*' | wc -l);
printf "\e[34mNumber Attached IPs:\e[0m %d\n" $(ip addr | grep -i 'inet\ ' | grep -v '127\.0\.0\.1' | wc -l);
printf "\e[34mMain IPs (interface : IP):\e[0m\n";

# Determine all the "main" interface IPs.
for inter in `ifconfig | grep -i '^e\(th\|np\).*' | cut -d ' ' -f1`; do 
    printf "\t\e[34m(\e[0m$inter \e[34m:\e[0m %s\e[34m)\e[0m\n" $(ifconfig "$inter" | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p');
done

printf "\n\e[34mTotal Traffic IN (per NIC):\e[0m\n";
for inter in `ifconfig | grep -i '^e\(th\|np\).*' | cut -d ' ' -f1 | cut -d : -f1 | uniq`; do 
    printf "\t$inter \e[34m<<\e[0m %s\n" $(cat /proc/net/dev | grep -i "$inter" | awk '{print $2}');
done

printf "\n\e[34mTotal Traffic OUT (per NIC):\e[0m\n";
for inter in `ifconfig | grep -i '^e\(th\|np\).*' | cut -d ' ' -f1 | cut -d : -f1 | uniq`; do 
    printf "\t$inter \e[34m>>\e[0m %s\n" $(cat /proc/net/dev | grep -i "$inter" | awk '{print $10}');
done

printf "\n\e[34mConnections:\e[0m\n";
ss -tuna | awk '{print $6}' | cut -d : -f1 | rev | grep -i '[0-9]\{1,3\}\..*' | rev | sort | uniq -c | sort -n | column -c 100;

if ((200 <= $(tput cols))) && ((NOCOL == 0)); then
    # Here we're gonna do something special.
    # Detect if the terminal column number is equal to or greater than 240 (length of iostat line * 2)
    COL=125;
    LINE=1;
    
    # Dump events and FS info.
    printf "\n\e[%d;%dH\e[1;35m= Event Details =\e[0m\n" $LINE $COL; LINE=$((++LINE));
    printf "\e[%d;%dH\e[35mCurrently Logged in:\e[0m\n" $LINE $COL; LINE=$((++LINE));
    for line in $(w | sed 's/ /_/g'); do
        line=$(echo "$line" | sed 's/_/ /g');
        printf "\e[%d;%dH %s" $LINE $COL "$line"; LINE=$((++LINE));
    done

    printf "\e[%d;%dH\e[35mLast Logins (last 10):\e[0m\n" $LINE $COL; LINE=$((++LINE));
    for line in $(last 2>&1 | head | sed 's/ /_/g'); do
        line=$(echo "$line" | sed 's/_/ /g');
        printf "\e[%d;%dH %s" $LINE $COL "$line"; LINE=$((++LINE));
    done
#    printf "\e[%d;%dH\e[1;35m= Event Details Cont.=\e[0m\n" $LINE $COL; LINE=$((++LINE));

    printf "\e[%d;%dH\e[35mLast 10 lines of DMesg:\e[0m\n" $LINE $COL; LINE=$((++LINE));
    for line in $(dmesg 2>&1 | tail | sed 's/ /_/g'); do
        line=$(echo "$line" | sed 's/_/ /g');
        printf "\e[%d;%dH %s" $LINE $COL "$line"; LINE=$((++LINE));
    done

    # FS Details.
    printf "\n\e[%d;%dH\e[1;36m= FS Details =\e[0m\n" $LINE $COL; LINE=$((++LINE));
    printf "\e[%d;%dH\e[36mDisk Usage (bytes):\e[0m\n" $LINE $COL; LINE=$((++LINE));
    for line in $(df -Th 2>&1 | sed 's/ /_/g'); do
        line=$(echo "$line" | sed 's/_/ /g');
        printf "\e[%d;%dH %s" $LINE $COL "$line"; LINE=$((++LINE));
    done

    printf "\e[%d;%dH\e[36mDisk Usage (inodes):\e[0m\n" $LINE $COL; LINE=$((++LINE));
    for line in $(df -Thi 2>&1 | sed 's/ /_/g'); do
        line=$(echo "$line" | sed 's/_/ /g');
        printf "\e[%d;%dH %s" $LINE $COL "$line"; LINE=$((++LINE));
    done

    printf "\e[%d;%dH\e[36mCurrent Mounts:\e[0m\n" $LINE $COL; LINE=$((++LINE));
    for line in $(cat /etc/mtab 2>&1 | awk '{print $1"\t"$2}' | grep -i '^\(\/dev\/\(s\|v\)d[a-z].*\|[0-9]\{1,3\}\..*\)' | sed 's/\040/ /g' | sed 's/ /_/g'); do
        line=$(echo "$line" | sed 's/_/ /g');
        printf "\e[%d;%dH %s" $LINE $COL "$line"; LINE=$((++LINE));
    done

    printf "\n\e[%d;%dH\e[43;30m= System Details =\e[0m\n" $LINE $COL; LINE=$((++LINE));
    printf "\e[%d;%dH\e[33mOS:\e[0m %s\n" $LINE $COL "$(uname -o)"; LINE=$((++LINE));
    printf "\e[%d;%dH\e[33mKernal:\e[0m %s\n" $LINE $COL "$(uname -sr)"; LINE=$((++LINE));
    printf "\e[%d;%dH\e[33mHostname:\e[0m %s\n" $LINE $COL "$(hostname)"; LINE=$((++LINE));
    printf "\e[%d;%dH\e[33mNumber Allowed Threads:\e[0m %d\n" $LINE $COL "$(sysctl kernel.pid_max | cut -d = -f2 | sed 's/ //g')"; LINE=$((++LINE));
    printf "\e[%d;%dH\e[33mNumber Threads (roughly):\e[0m %d\n" $LINE $COL "$(ps auxhH | wc -l)"; LINE=$((++LINE));
    printf "\e[%d;%dH" $((`tput lines`)) 0;
else
    # Dump events and FS info.
    printf "\n\e[1;35m= Event Details =\e[0m\n";
    printf "\e[35mCurrently Logged in:\e[0m\n";
    w;

    printf "\e[35mLast Logins (last 10):\e[0m\n";
    last | head;
    
    printf "\e[35mLast 10 lines of DMesg:\e[0m\n";
    dmesg | tail;

    # FS Details.
    printf "\n\e[1;36m= FS Details =\e[0m\n";
    printf "\e[36mDisk Usage (bytes):\e[0m\n";
    df -Th;

    printf "\e[36mDisk Usage (inodes):\e[0m\n";
    df -Thi;

    printf "\e[36mCurrent Mounts:\e[0m\n";
    cat /etc/mtab | awk '{print $1"\t"$2}' | grep -i '^\(\/dev\/\(s\|v\)d[a-z].*\|[0-9]\{1,3\}\..*\)' | sed 's/\040/ /g';

    printf "\n\e[43;30m= System Details =\e[0m\n";
    printf "\e[33mOS:\e[0m %s\n" "$(uname -o)";
    printf "\e[33mKernal:\e[0m %s\n" "$(uname -sr)";
    printf "\e[33mHostname:\e[0m %s\n" "$(hostname)";
    printf "\e[33mNumber Allowed Threads:\e[0m %d\n" "$(sysctl kernel.pid_max | cut -d = -f2 | sed 's/ //g')";
    printf "\e[33mNumber Threads (roughly):\e[0m %d\n" "$(ps auxhH | wc -l)";
fi
