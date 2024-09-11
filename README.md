> This project presents proof of concept for using eBPF to bypass container overlay networks in the paper titled "Bypass Container Overlay Networks with Transparent BPF-driven Socket Replacement" which has been published in IEEE CLOUD 2022 (https://ieeexplore.ieee.org/document/9860379).

# eBPF-Router
This is a daemon process to bypass overlay network layer with outside-in socket redirection technique based on tracing tools (eBPF and Ptrace).
You can test with simple two steps: (1) modify environment variables and deploy the daemonset with pre-built image to the cluster and (2) run the test script

## 1. Deploy to the cluster

#### Option 1: with daemonset

1. Modify environment variables in `deploy/simple-ds.yaml`
    
    |**Networks**|Description|
    |---|---|
    |OVERLAY_IF|interface that can link overlay networks to host-level networks  (e.g, vxlan.calico for VX-LAN, ens3 for IPIP) |
    |HOST_IF|interface for creating host connection (e.g., ens3, eth0)|
    |ROUTER_PORT|any available port on host for coordinating (default: 1234)|

    |**Logging**|Description|
    |---|---|
    |ROUTER_LOGLEVEL|logging level which can be INFO or DEBUG or WARNING or ERROR|

2. Define and Deploy rules (configmap) for defining which process or connection would be applied to this router

   ```
   data:
    <rule name>: |
      type=<cidr|podLabel|containerLabel>
      # for podLabel and containerLabel
      name=<label name>
      value=<label value>
      # for cidr
      from=<from(server) cidr>
      to=<to(client) cidr>
      reverse=<true|false>
   ```
   see example in `deploy/rules.yaml`

  - podLabel and containerLabel will be treated as a filter rules while cidr will be treated as a validate rules
  - the filter rules will be applied first, then, apply the validate rules
  - If no filter rules, all are filtered in (similarly for validate rules)
(check [util/ruler.py](util/ruler.py))


3. Specify image in `deploy/simple-ds.yaml`
    The pre-built image is available in 
   `ghcr.io/ibm/ebpf-router/router:v0.0.1`

    To build your own image:
    2.1. Clone this repository

     ``` 
     git clone https://github.com/IBM/ebpf-router-ieee-cloud-2022.git
     ```
    
    2.2. Run `init.sh` to make all relevant binary files on your worker OS
    
    ```
    chmod +x init.sh
    ./init.sh
    tar cvf router.tar dist
    ```
    
    2.3. Modify the base OS image on `Dockerfile` and Build and push image 
    
    ```
    docker build -t ebpf-router/router .
    docker image tag ebpf-router/router [remote repository]/ebpf-router/router
    docker push [remote repository]/ebpf-router/router
    ```

4. Deploy the daemonset
```
kubectl create -f deploy/simple-ds.yaml
```

4. To uninstall, just delete the deamonset
```
kubectl delete -f deploy/simple-ds.yaml
```

#### Option 2: local run [ for each host ]

1. Export environments

2. Run the forwarder and router 
   1. From binary, [build_instruction](/src/README.md)
        ```
        cd src
        chmod +x init.sh
        ./init.sh
        ./forwarder & ./dist/router/router
        ```
   2. From python
        ```
        cd src
        ./forwarder & python3 router.py
        ```

## 2. Test with Benchmarks

Run [script.sh](./test/script.sh) in test folder
#### action required:
1. deploy secret resource to pull image from res-cpe-team-docker-local.artifactory.swg-devops.com repo
2. modify node selector (replace master/worker role)

To test with eBPF router, you can run the above benchmark with 
```
./script.sh test [benchmark key] [daemonset yaml file]

for example,
./script.sh test iperf3 ../deploy/simple-ds.yaml
```

To test without eBPF router, delete daemonset first then deploy and run the benchmark
```
kubectl delete ds ebpf-router -nkube-system
./script.sh deploy_and_run [benchmark key]
```
See client log by
```
./script.sh log [benchmark key]
```

|**Benchmark**|Key|Job|Remark
|---|---|---|---|
|Iperf 3|iperf3|[iperfclientf1](./test/iperf3/client-job-template.yaml)|role:worker connect to iperf server with role:master|
|MPI P2P Latency|mpilat|[osu-benchmark](./test/mpi/mpilat.yaml)|run with mpi-operator (role:worker)|
|MPI P2P Bandwidth|mpibw|[osu-benchmark-bw](./test/mpi/mpibw.yaml)|run with mpi-operator (role:worker)|
|MPI All-to-All Latency|mpiall|[osu-benchmark](./test/mpi/mpiall.yaml)|run with mpi-operator (no selector)|
|Memcached|memcached|[memaslap_job.yaml](./test/memcached/memaslap_job.yaml)|**requirement:** [helm chart installation](https://helm.sh/docs/intro/install/) with https://charts.helm.sh/stable repo <br>`helm repo add stable https://charts.helm.sh/stable`<br>`helm repo update`<br>(role:master connect to memcached-0)|

# References
* [Slim](https://github.com/danyangz/Slim): OS Kernel Support for a Low-Overhead Container Overlay Network
* [ptrace_do](https://github.com/emptymonkey/ptrace_do): Ptrace library designed to simplify syscall injection in Linux.

## Citation
Please you the following citation to cite this work:


> S. Choochotkaew, T. Chiba, S. Trent and M. Amaral, "Bypass Container Overlay Networks with Transparent BPF-driven Socket Replacement," 2022 IEEE 15th International Conference on Cloud Computing (CLOUD), Barcelona, Spain, 2022, pp. 134-143, doi: 10.1109/CLOUD55607.2022.00033.