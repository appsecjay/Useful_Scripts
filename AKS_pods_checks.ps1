# Required Azure PowerShell module
Import-Module Az

# Authentication
Connect-AzAccount

# Define the resource groups and cluster names 
#Replace resource name and clustername
$clusters = @(
    @{ResourceGroupName = "RG-1"; ClusterName = "Cl-name1"},
    @{ResourceGroupName = "RG-2"; ClusterName = "cl-name2"}
)

# Function to perform security checks on a pod
function PerformSecurityChecks($pod) {
    $namespace = $pod.metadata.namespace
    $podName = $pod.metadata.name
    $containers = $pod.spec.containers

    foreach ($container in $containers) {
        $containerName = $container.name
        $securityContext = $container.securityContext

        # Check if the container is running as a non-root user
        if ($securityContext -and $securityContext.runAsUser -ne 0) {
            Write-Host "PASS: Namespace: $namespace, Pod: $podName, Container: $containerName is running as non-root user." -ForegroundColor Green
        } else {
            Write-Host "FAIL: Namespace: $namespace, Pod: $podName, Container: $containerName is running as root user." -ForegroundColor Red
        }

        # Check if the container has resource limits defined
        if ($container.resources -and $container.resources.limits) {
            Write-Host "PASS: Namespace: $namespace, Pod: $podName, Container: $containerName has resource limits defined." -ForegroundColor Green
        } else {
            Write-Host "FAIL: Namespace: $namespace, Pod: $podName, Container: $containerName does not have resource limits defined." -ForegroundColor Red
        }

        # Check if the container has a security context defined
        if ($securityContext) {
            Write-Host "PASS: Namespace: $namespace, Pod: $podName, Container: $containerName has security context defined." -ForegroundColor Green
        } else {
            Write-Host "FAIL: Namespace: $namespace, Pod: $podName, Container: $containerName does not have security context defined." -ForegroundColor Red
        }
    }
}

# Function to list all pods in all namespaces for a cluster and perform security checks
function ListPodsAndPerformChecks($resourceGroupName, $clusterName) {
    Write-Host "Listing all pods in all namespaces for AKS cluster: $clusterName in resource group: $resourceGroupName" -ForegroundColor Cyan

    # Get AKS credentials
    az aks get-credentials --resource-group $resourceGroupName --name $clusterName --overwrite-existing

    # List all pods in all namespaces
    $pods = kubectl get pods --all-namespaces -o json

    # Parse the pods information
    $podList = $pods | ConvertFrom-Json

    # Perform security checks on each pod
    foreach ($pod in $podList.items) {
        PerformSecurityChecks -pod $pod
    }
}

# Loop through each cluster and list all pods and perform security checks
foreach ($cluster in $clusters) {
    ListPodsAndPerformChecks -resourceGroupName $cluster.ResourceGroupName -clusterName $cluster.ClusterName
}
