## PyInstaller
## caution:
##      - missing module named: xxx
##      - cannot handle interrupt signal between process (https://github.com/pyinstaller/pyinstaller/issues/3646)

rm -r dist
rm -r build

IMAGE_PREFIX="ghcr.io/ibm/ebpf-router/router"
VERSION="v0.0.1"

ubuntu(){
    pyinstaller router.py
    pyinstaller pt/ptrace_handler.py
    rm router.tar
    tar cf router.tar dist
    
    cd src
    make clean
    cd ..

    IMAGE=$IMAGE_PREFIX-ubuntu

    IMAGE_VERSION=$IMAGE:$VERSION
    docker build -t $IMAGE_VERSION -f docker/Dockerfile.ubuntu .
    docker push $IMAGE_VERSION
}

"$@"
date