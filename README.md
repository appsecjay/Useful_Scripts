#Usage:
Save the script to a file (e.g., extract_public_subnets.py). Then, you can run it from the command line like this:
python extract_public_subnets.py input_file.txt output_file.txt

Replace input_file.txt with the path to your input file containing IP subnets, and output_file.txt will contain the extracted public IP subnets.

#AKS Security Check covers 
1.Kubernetes Dashboard is disabled
2.RBAC is enabled
3.Azure AD integration is enabled
4.Network Policies are enabled
5.API server authorized IP ranges are set
6.Secrets are encrypted with Customer Managed Keys
7.Azure Policy Add-on is enabled
8.Ingress controllers are secured
9.Kubernetes version is up-to-date
10.TLS versions and ciphers are secure
11.Audit logs are enabled
12.VNET integration is enabled
13.Private cluster is enabled
14.Cluster autoscaler is enabled
15.Managed identities are used
16.Logging and monitoring are enabled
17.Pod security policies are enabled
18.Secrets encryption is enabled
19.AKS cluster is using managed disks.
Each check includes a description, the result of the check, and a recommendation if the check fails. This script will generate a comprehensive security assessment report for your AKS cluster.
