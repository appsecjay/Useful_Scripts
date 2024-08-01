# Define the resource group and AKS cluster name Replace below variables.
$resourceGroupName = "rg-name"
$aksClusterName = "aksclustername"

# Define the output file
$outputFile = "AKS_Security_Assessment_Report.txt"

# Start the assessment and write the header to the output file
Start-Transcript -Path $outputFile -Append
Write-Host "Starting AKS Security Assessment for Cluster: $aksClusterName in Resource Group: $resourceGroupName" -ForegroundColor Cyan
Write-Host "------------------------------------------------------------------" -ForegroundColor Cyan

# Function to write check results to the output file
function Write-CheckResult {
    param (
        [string]$checkDescription,
        [string]$result,
        [string]$recommendation
    )
    Write-Host "Check: $checkDescription" -ForegroundColor Yellow
    Write-Host "Result: $result" -ForegroundColor Green
    Write-Host "Recommendation: $recommendation" -ForegroundColor Red
    Write-Host "------------------------------------------------------------------" -ForegroundColor Cyan
}

# Check 1: Ensure Kubernetes Dashboard is disabled
$dashboardEnabled = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "addonProfiles.kubeDashboard.enabled" -o tsv
if ($dashboardEnabled -eq "false") {
    Write-CheckResult "Kubernetes Dashboard is Disabled" "Pass" "No action needed"
} else {
    Write-CheckResult "Kubernetes Dashboard is Enabled" "Fail" "Disable the Kubernetes Dashboard using 'az aks disable-addons --addons kube-dashboard --resource-group $resourceGroupName --name $aksClusterName'"
}

# Check 2: Ensure RBAC is enabled
$rbacEnabled = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "enableRBAC" -o tsv
if ($rbacEnabled -eq "true") {
    Write-CheckResult "RBAC is Enabled" "Pass" "No action needed"
} else {
    Write-CheckResult "RBAC is Disabled" "Fail" "Enable RBAC using 'az aks update --resource-group $resourceGroupName --name $aksClusterName --enable-rbac'"
}

# Check 3: Ensure Azure AD integration is enabled
$aadProfile = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "aadProfile" -o tsv
if ($aadProfile) {
    Write-CheckResult "Azure AD Integration is Enabled" "Pass" "No action needed"
} else {
    Write-CheckResult "Azure AD Integration is Disabled" "Fail" "Enable Azure AD integration using 'az aks update --resource-group $resourceGroupName --name $aksClusterName --enable-aad --aad-admin-group-object-ids <group-object-id> --aad-tenant-id <tenant-id>'"
}

# Check 4: Ensure Network Policies are enabled
$networkPlugin = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "networkProfile.networkPlugin" -o tsv
$networkPolicy = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "networkProfile.networkPolicy" -o tsv
if ($networkPlugin -eq "azure" -and $networkPolicy -eq "calico") {
    Write-CheckResult "Network Policies are Enabled" "Pass" "No action needed"
} else {
    Write-CheckResult "Network Policies are Disabled" "Fail" "Enable Network Policies using 'az aks update --resource-group $resourceGroupName --name $aksClusterName --network-policy calico'"
}

# Check 5: Ensure API server authorized IP ranges are set
$apiServerAuthorizedIpRanges = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "apiServerAccessProfile.authorizedIpRanges" -o tsv
if ($apiServerAuthorizedIpRanges) {
    Write-CheckResult "API Server Authorized IP Ranges are Set" "Pass" "No action needed"
} else {
    Write-CheckResult "API Server Authorized IP Ranges are Not Set" "Fail" "Set API server authorized IP ranges using 'az aks update --resource-group $resourceGroupName --name $aksClusterName --api-server-authorized-ip-ranges <ip-ranges>'"
}

# Check 6: Ensure Secrets are encrypted with Customer Managed Keys
$enablePodSecurityPolicy = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "podSecurityPolicy" -o tsv
if ($enablePodSecurityPolicy -eq "true") {
    Write-CheckResult "Pod Security Policies are Enabled" "Pass" "No action needed"
} else {
    Write-CheckResult "Pod Security Policies are Disabled" "Fail" "Enable Pod Security Policies using 'az aks update --resource-group $resourceGroupName --name $aksClusterName --enable-pod-security-policy'"
}

# Check 7: Ensure Azure Policy Add-on is enabled
$azurePolicyEnabled = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "addonProfiles.azurepolicy.enabled" -o tsv
if ($azurePolicyEnabled -eq "true") {
    Write-CheckResult "Azure Policy Add-on is Enabled" "Pass" "No action needed"
} else {
    Write-CheckResult "Azure Policy Add-on is Disabled" "Fail" "Enable Azure Policy Add-on using 'az aks enable-addons --addons azure-policy --resource-group $resourceGroupName --name $aksClusterName'"
}

# Check 8: Ensure ingress controllers are secured
$ingressControllers = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "ingressProfiles" -o tsv
if ($ingressControllers) {
    Write-CheckResult "Ingress Controllers are Configured" "Pass" "Ensure ingress controllers are configured with HTTPS and security best practices"
} else {
    Write-CheckResult "Ingress Controllers are Not Configured" "Fail" "Configure ingress controllers with HTTPS and security best practices"
}

# Additional Checks:
# Check 9: Ensure Kubernetes version is up-to-date
$k8sVersion = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "kubernetesVersion" -o tsv
$latestVersion = az aks get-versions --location eastus --query "orchestrators[-1].orchestratorVersion" -o tsv
if ($k8sVersion -eq $latestVersion) {
    Write-CheckResult "Kubernetes Version is Up-to-date" "Pass" "No action needed"
} else {
    Write-CheckResult "Kubernetes Version is Not Up-to-date" "Fail" "Upgrade Kubernetes version using 'az aks upgrade --resource-group $resourceGroupName --name $aksClusterName --kubernetes-version $latestVersion'"
}

# Check 10: Ensure TLS versions and ciphers are secure
$apiServerTlsVersion = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "apiServerAccessProfile.tlsVersions" -o tsv
if ($apiServerTlsVersion -match "TLS1_2|TLS1_3") {
    Write-CheckResult "TLS Versions are Secure" "Pass" "No action needed"
} else {
    Write-CheckResult "TLS Versions are Not Secure" "Fail" "Update TLS versions to use TLS 1.2 or TLS 1.3"
}

# Check 11: Ensure audit logs are enabled
$auditLogsEnabled = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "enableAuditLogs" -o tsv
if ($auditLogsEnabled -eq "true") {
    Write-CheckResult "Audit Logs are Enabled" "Pass" "No action needed"
} else {
    Write-CheckResult "Audit Logs are Disabled" "Fail" "Enable audit logs using 'az aks update --resource-group $resourceGroupName --name $aksClusterName --enable-audit-logs'"
}

# Check 12: Ensure VNET integration is enabled
$vnetIntegration = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "networkProfile.vnetSubnetId" -o tsv
if ($vnetIntegration) {
    Write-CheckResult "VNET Integration is Enabled" "Pass" "No action needed"
} else {
    Write-CheckResult "VNET Integration is Disabled" "Fail" "Enable VNET integration using 'az aks update --resource-group $resourceGroupName --name $aksClusterName --vnet-subnet-id <subnet-id>'"
}

# Check 13: Ensure private cluster is enabled
$privateClusterEnabled = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "apiServerAccessProfile.enablePrivateCluster" -o tsv
if ($privateClusterEnabled -eq "true") {
    Write-CheckResult "Private Cluster is Enabled" "Pass" "No action needed"
} else {
    Write-CheckResult "Private Cluster is Disabled" "Fail" "Enable private cluster using 'az aks update --resource-group $resourceGroupName --name $aksClusterName --enable-private-cluster'"
}

# Check 14: Ensure cluster autoscaler is enabled
$autoscalerEnabled = az aks nodepool show --resource-group $resourceGroupName --cluster-name $aksClusterName --name nodepool1 --query "enableAutoScaling" -o tsv
if ($autoscalerEnabled -eq "true") {
    Write-CheckResult "Cluster Autoscaler is Enabled" "Pass" "No action needed"
} else {
    Write-CheckResult "Cluster Autoscaler is Disabled" "Fail" "Enable cluster autoscaler using 'az aks nodepool update --resource-group $resourceGroupName --cluster-name $aksClusterName --name nodepool1 --enable-cluster-autoscaler --min-count <min-count> --max-count <max-count>'"
}

# Check 15: Ensure managed identities are used
$identityType = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "identity.type" -o tsv
if ($identityType -eq "UserAssigned") {
    Write-CheckResult "Managed Identities are Used" "Pass" "No action needed"
} else {
    Write-CheckResult "Managed Identities are Not Used" "Fail" "Use managed identities by updating the cluster identity type to 'UserAssigned'"
}

# Check 16: Ensure logging and monitoring are enabled
$monitoringEnabled = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "addonProfiles.omsagent.enabled" -o tsv
if ($monitoringEnabled -eq "true") {
    Write-CheckResult "Logging and Monitoring are Enabled" "Pass" "No action needed"
} else {
    Write-CheckResult "Logging and Monitoring are Disabled" "Fail" "Enable logging and monitoring using 'az aks enable-addons --addons monitoring --resource-group $resourceGroupName --name $aksClusterName'"
}

# Check 17: Ensure pod security policies are enabled
$podSecurityPoliciesEnabled = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "podSecurityPolicy.enabled" -o tsv
if ($podSecurityPoliciesEnabled -eq "true") {
    Write-CheckResult "Pod Security Policies are Enabled" "Pass" "No action needed"
} else {
    Write-CheckResult "Pod Security Policies are Disabled" "Fail" "Enable pod security policies using 'az aks update --resource-group $resourceGroupName --name $aksClusterName --enable-pod-security-policy'"
}

# Check 18: Ensure secrets encryption is enabled
$secretsEncryption = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "enableEncryptionAtHost" -o tsv
if ($secretsEncryption -eq "true") {
    Write-CheckResult "Secrets Encryption is Enabled" "Pass" "No action needed"
} else {
    Write-CheckResult "Secrets Encryption is Disabled" "Fail" "Enable secrets encryption using 'az aks update --resource-group $resourceGroupName --name $aksClusterName --enable-encryption-at-host'"
}

# Check 19: Ensure AKS cluster is using managed disks
$useManagedDisks = az aks show --resource-group $resourceGroupName --name $aksClusterName --query "diskEncryptionSetID" -o tsv
if ($useManagedDisks) {
    Write-CheckResult "Managed Disks are Used" "Pass" "No action needed"
} else {
    Write-CheckResult "Managed Disks are Not Used" "Fail" "Use managed disks by updating the cluster to use disk encryption sets"
}

# Concluding the assessment
Write-Host "AKS Security Assessment Completed" -ForegroundColor Cyan
Stop-Transcript

# Open the output file to review the assessment
Invoke-Item $outputFile
