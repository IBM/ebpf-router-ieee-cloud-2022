# Build from source

#### Test environment
|OS|Linux Kernel|
|---|---|
|Ubuntu|4.15.0-136-generic|

#### Build and Environement Setting

1. Initially set environment and build binary files
    ```
    chmod +x init.sh
    ./init.sh
    ```

The following items will be installed and built
*  make, gcc, build-essential, jq
*  bcc tools
*  python3-bcc, python3-pip
*  python packages listed in requirement.txt
*  ptrace_do packages, forward_fd
*  set OVERLAY_CIRD from maximum-priority of cni

[ optional ] install pyinstaller, make python binary of router and corresponding calls. 
 - The result binary and its dependencies will be in `dist`

2. Recompile, build and push image
    ```
    chmod +x recompile_build_push.sh
    ./recompile_build_push.sh
    ```