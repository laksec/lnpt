### 9.2 Kubernetes Enumeration
    # Check client and server version
    kubectl version
    
    # Get cluster endpoint and services info
    kubectl cluster-info
    
    # List nodes in the cluster with IPs
    kubectl get nodes -o wide
    
    # List all namespaces
    kubectl get namespaces
    
    # List pods in a namespace with node info
    kubectl get pods -n <namespace> -o wide
    
    # List services in a namespace
    kubectl get services -n <namespace>
    
    # List secrets (check permissions!)
    kubectl get secrets -n <namespace>
    
    # List RBAC roles and bindings
    kubectl get roles,rolebindings -n <namespace>
    
    # List configmaps (may contain config/sensitive data)
    kubectl get configmaps -n <namespace>
    
    # Check current user's permissions in a namespace
    kubectl auth can-i --list --namespace=<namespace>
    
    # Get detailed info about a pod (env vars, volumes)
    kubectl describe pod <pod_name> -n <namespace>
    
    # View logs for a pod
    kubectl logs <pod_name> -n <namespace>

    # Finding Exposed K8s API Servers (via Shodan/Censys etc.)    
    Search for: "product:kubernetes" "port:443" "ssl:kube-apiserver"
    Search for: "port:10250" "kubelet" (Kubelet read-only port)