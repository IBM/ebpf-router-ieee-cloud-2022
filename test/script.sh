################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

wait_ready()
{
    ready=$(kubectl get ds -n $2 $1 -o json|jq -r '.status.numberReady')
    desired=$(kubectl get ds -n $2 $1 -o json|jq -r '.status.desiredNumberScheduled')
    echo Wait $1 ns=$2 to be ready
    while [ $ready != $desired ]
    do 
        ready=$(kubectl get ds -n $2 $1 -o json|jq -r '.status.numberReady')
        sleep 5
    done
}

wait_clean()
{
    found=$(kubectl get po -n $2|grep $1|wc -l)
    echo Wait $1 ns=$2 to clean
    while [ $found != "0" ]
    do
      found=$(kubectl get po -n $2 |grep $1|wc -l)
      sleep 5
    done
}

wait_for_start()
{
    pod=$1
    found=$(kubectl get po $pod|wc -l)
    echo Wait $pod to be available
    while [ $found == "0" ]
    do
      found=$(kubectl get po $pod|wc -l)
      sleep 10
    done

    echo Wait the first container of $pod to start
    start=$(kubectl get po $pod -ojson|jq -r '.status.containerStatuses[0].started')
    while [ $start != "true" ]
    do
        start=$(kubectl get po $pod -ojson|jq -r '.status.containerStatuses[0].started')
        sleep 10
    done
}

wait_for_job_done()
{   
    job=$1
    echo Wait the first container of $job to be succeeded    
    succeeded=$(kubectl get job $job -ojson|jq -r '.status.succeeded')
    while [ $succeeded != "1" ]
    do
        succeeded=$(kubectl get job $job -ojson|jq -r '.status.succeeded')
        sleep 10
    done
}

clean_iperf3()
{
    kubectl delete -f iperf3/client-job.yaml
    kubectl delete -f iperf3/server.yaml
}

deploy_iperf3()
{
    echo ""
}

run_iperf3()
{
    SERVER_POD=iperfserverf1
    kubectl create -f iperf3/server.yaml
    wait_for_start ${SERVER_POD}
    SERVER_IP=$(kubectl get po ${SERVER_POD} -ojson|jq -r '.status.podIPs[0]["ip"]')
    echo "Replace SERVER IP ${SERVER_IP}"
    sed "s/SERVER_IP/${SERVER_IP}/g" iperf3/client-job-template.yaml > iperf3/client-job.yaml
    kubectl create -f iperf3/client-job.yaml
    wait_for_job_done iperfclientf1
}

log_iperf3()
{
    kubectl logs job/iperfclientf1
}

##### Memcached ####################

clean_memcached()
{
    helm uninstall memcached
    kubectl delete -f memcached/memaslap_job.yaml
    wait_clean memcached default
}

deploy_memcached()
{
    helm install memcached stable/memcached
    for i in {0..2}
    do
        wait_for_start memcached-$i
    done
    echo "All started."
    sleep 10
    kubectl get po -owide -l app.kubernetes.io/name=memcached
    
}

run_memcached()
{
    kubectl delete -f memcached/memaslap_job.yaml
    kubectl create -f memcached/memaslap_job.yaml
    wait_for_job_done memslap-driver
}

run_slim_memcached()
{
    kubectl create -f memcached/memaslap_slim.yaml
    wait_for_job_done memslap-driver
}

load_memcached()
{
    name=$2
    for env in $(kubectl get job memslap-driver -ojson|jq -r '.spec.template.spec.containers[0].env[]|.value')
    do
        name=${name}_${env}
    done
    kubectl logs job/memslap-driver > memcached/results/${name}.log
}

log_memcached()
{
    kubectl logs job/memslap-driver
}

########################################

##### MPI ##############################

# Latency
deploy_mpi()
{

    mp_count=$(kubectl get deploy mpi-operator -n mpi-operator|wc -l)
    if [ $mp_count == "2" ]; then
        echo "MPI operator has been already deployed"
    else
        cd /tmp
        git clone https://github.com/kubeflow/mpi-operator
        cd mpi-operator
        kubectl create -f deploy/v1alpha2/mpi-operator.yaml
        cd ..
        rm -r mpi-operator
    fi
}

run_mpi()
{
    kubectl delete -f mpi/$1.yaml
    kubectl create -f mpi/$1.yaml
    wait_for_job_done $2
}

deply_mpilat()
{
    deploy_mpi
}

deploy_mpibw()
{
    deploy_mpi
}

deploy_mpiall()
{
    deploy_mpi
}


run_mpilat()
{
    run_mpi mpilat osu-benchmark-launcher
}

run_mpibw()
{
    run_mpi mpibw osu-benchmark-bw-launcher
}

run_mpiall()
{
    run_mpi mpiall osu-benchmark-launcher
}

clean_mpilat()
{
    kubectl delete -f mpi/mpilat.yaml
}

clean_mpibw()
{
    kubectl delete -f mpi/mpibw.yaml
}

clean_mpiall()
{
    kubectl delete -f mpi/mpiall.yaml
}


load_mpilat()
{
    kubectl logs job/osu-benchmark-launcher > mpi/results/$2_lat_$3.log
}

load_mpibw()
{
    kubectl logs job/osu-benchmark-bw-launcher > mpi/results/$2_bw_$3.log
}

load_mpiall()
{
    kubectl logs job/osu-benchmark-launcher > mpi/results/$2_all_$3.log
}


log_mpilat()
{
    kubectl logs job/osu-benchmark-launcher
}

log_mpibw()
{
    kubectl logs job/osu-benchmark-bw-launcher
}

log_mpiall()
{
    kubectl logs job/osu-benchmark-launcher
}

########################################

deploy()
{
    deploy_$1 $@
}

clean()
{
    clean_$1
}

run()
{
    run_$1 $@
}

run_slim()
{
    run_slim_$1 $@
}


load()
{
    load_$1 $@  
} 

deploy_and_run()
{
    clean_$1 $@ 
    deploy_$1 $@
    run_$1 $@
}

deploy_and_run_slim()
{
    clean_$1 $@ 
    deploy_$1 $@
    run_slim_$1 $@
}

check_log()
{
    log_$1
}



test(){
    clean $1
    kubectl delete -f $2
    wait_clean ebpf-router kube-system
    kubectl create -f $2
    wait_ready ebpf-router kube-system
    deploy_and_run $1
}

"$@"