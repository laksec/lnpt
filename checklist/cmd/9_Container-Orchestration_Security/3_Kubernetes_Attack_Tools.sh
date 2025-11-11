### 9.3 Kubernetes Attack Tools
    # Tool for auditing K8s clusters (various checks)
    cd_k8s_audit
    
    # Scan K8s cluster for security issues (from outside)
    kube-hunter --remote <node_ip_or_dns>
    
    # Run kube-hunter from within a pod
    kube-hunter --pod
    kubesploit (Metasploit-like framework for K8s)