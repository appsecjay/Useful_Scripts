# Authenticate to Azure
Connect-AzAccount

# Define the resource groups and cluster names
$clusters = @(
    @{ResourceGroupName = "RG-1"; ClusterName = "CL-1"},
    @{ResourceGroupName = "RG-2"; ClusterName = "CL-2"}
)

# Loop through each cluster and perform security checks
foreach ($cluster in $clusters) {
    $resourceGroupName = $cluster.ResourceGroupName
    $clusterName = $cluster.ClusterName

    Write-Host "Checking security for AKS cluster: $clusterName in resource group: $resourceGroupName" -ForegroundColor Cyan

    # 1. Check RBAC enabled
    $rbacEnabled = (az aks show --resource-group $resourceGroupName --name $clusterName --query "enableRBAC" -o tsv)
    if ($rbacEnabled -eq "true") {
        Write-Host "RBAC is enabled." -ForegroundColor Green
    } else {
        Write-Host "RBAC is not enabled." -ForegroundColor Red
    }

    # 2. Check Network Policy
    $networkPolicy = (az aks show --resource-group $resourceGroupName --name $clusterName --query "networkProfile.networkPolicy" -o tsv)
    if ($networkPolicy -ne "") {
        Write-Host "Network Policy is set to: $networkPolicy" -ForegroundColor Green
    } else {
        Write-Host "Network Policy is not set." -ForegroundColor Red
    }

    # 3. Check API Server Authorized IP Ranges
    $apiServerAuthorizedIpRanges = (az aks show --resource-group $resourceGroupName --name $clusterName --query "apiServerAccessProfile.authorizedIpRanges" -o tsv)
    if ($apiServerAuthorizedIpRanges) {
        Write-Host "API Server Authorized IP Ranges: $apiServerAuthorizedIpRanges" -ForegroundColor Green
    } else {
        Write-Host "API Server Authorized IP Ranges are not set." -ForegroundColor Red
    }

    # 4. Check for HTTPS only
    $httpsOnly = (az aks show --resource-group $resourceGroupName --name $clusterName --query "addonProfiles.httpApplicationRouting.config.httpsOnly" -o tsv)
    if ($httpsOnly -eq "true") {
        Write-Host "HTTPS only is enabled." -ForegroundColor Green
    } else {
        Write-Host "HTTPS only is not enabled." -ForegroundColor Red
    }

    # 5. Check Azure Policy Add-on
    $azurePolicyAddon = (az aks show --resource-group $resourceGroupName --name $clusterName --query "addonProfiles.azurePolicy.enabled" -o tsv)
    if ($azurePolicyAddon -eq "true") {
        Write-Host "Azure Policy Add-on is enabled." -ForegroundColor Green
    } else {
        Write-Host "Azure Policy Add-on is not enabled." -ForegroundColor Red
    }

    # 6. Check Kubernetes Version
    $kubernetesVersion = (az aks show --resource-group $resourceGroupName --name $clusterName --query "kubernetesVersion" -o tsv)
    Write-Host "Kubernetes Version: $kubernetesVersion" -ForegroundColor Green

    # 7. Check for Ingress Controller
    $ingressAddon = (az aks show --resource-group $resourceGroupName --name $clusterName --query "addonProfiles.httpApplicationRouting.enabled" -o tsv)
    if ($ingressAddon -eq "true") {
        Write-Host "Ingress Controller is deployed." -ForegroundColor Green
    } else {
        Write-Host "Ingress Controller is not deployed." -ForegroundColor Red
    }

    # 8. Check for ACR integration
    $acrName = "yourACRName"
    $acrLoginServer = (az acr show --name $acrName --query "loginServer" -o tsv)
    $acrIntegration = (az aks show --resource-group $resourceGroupName --name $clusterName --query "servicePrincipalProfile.clientId" -o tsv | % {az role assignment list --assignee $_ --scope $(az acr show --name $acrName --query "id" -o tsv) --query "[].roleDefinitionName" -o tsv})
    if ($acrIntegration -contains "AcrPull") {
        Write-Host "ACR integration is configured correctly." -ForegroundColor Green
    } else {
        Write-Host "ACR integration is not configured correctly." -ForegroundColor Red
    }

    # 9. Check for Monitoring
    $monitoringAddon = (az aks show --resource-group $resourceGroupName --name $clusterName --query "addonProfiles.omsagent.enabled" -o tsv)
    if ($monitoringAddon -eq "true") {
        Write-Host "Monitoring is enabled." -ForegroundColor Green
    } else {
        Write-Host "Monitoring is not enabled." -ForegroundColor Red
    }

    # 10. Check for Pod Security Policies
    Write-Host "Pod Security Policies cannot be checked due to missing kubectl." -ForegroundColor Yellow

    # 11. Check Cluster Upgrade Policy
    $upgradePolicy = (az aks show --resource-group $resourceGroupName --name $clusterName --query "autoUpgradeProfile.upgradeChannel" -o tsv)
    if ($upgradePolicy -ne "") {
        Write-Host "Cluster Upgrade Policy is set to: $upgradePolicy" -ForegroundColor Green
    } else {
        Write-Host "Cluster Upgrade Policy is not configured." -ForegroundColor Red
    }

    # 12. Check Azure AD Integration
    $aadIntegration = (az aks show --resource-group $resourceGroupName --name $clusterName --query "aadProfile" -o tsv)
    if ($aadIntegration) {
        Write-Host "Azure AD integration is enabled." -ForegroundColor Green
    } else {
        Write-Host "Azure AD integration is not enabled." -ForegroundColor Red
    }

    # 13. Check for NSG Rules
    $subnets = (az network vnet subnet list --resource-group $resourceGroupName --vnet-name $(az aks show --resource-group $resourceGroupName --name $clusterName --query "networkProfile.vnetSubnetId" -o tsv | Split-Path -Leaf) --query "[].{Name:name}" -o tsv)
    if ($subnets) {
        foreach ($subnet in $subnets) {
            $nsg = (az network vnet subnet show --resource-group $resourceGroupName --vnet-name $(az aks show --resource-group $resourceGroupName --name $clusterName --query "networkProfile.vnetSubnetId" -o tsv | Split-Path -Leaf) --name $subnet --query "networkSecurityGroup.id" -o tsv)
            if ($nsg) {
                Write-Host "NSG associated with subnet ${subnet}: ${nsg}" -ForegroundColor Green
            } else {
                Write-Host "No NSG associated with subnet ${subnet}." -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No subnets found for the cluster." -ForegroundColor Red
    }

    # 14. Check for Cluster Encryption
    $encryption = (az aks show --resource-group $resourceGroupName --name $clusterName --query "securityProfile" -o tsv)
    if ($encryption) {
        Write-Host "Cluster Encryption Profile: $encryption" -ForegroundColor Green
    } else {
        Write-Host "Cluster Encryption is not configured." -ForegroundColor Red
    }

    # 15. Check for Private Cluster
    $privateCluster = (az aks show --resource-group $resourceGroupName --name $clusterName --query "apiServerAccessProfile.privateCluster" -o tsv)
    if ($privateCluster -eq "true") {
        Write-Host "Private Cluster is enabled." -ForegroundColor Green
    } else {
        Write-Host "Private Cluster is not enabled." -ForegroundColor Red
    }

    # 16. Check for Managed Identity Configuration
    $managedIdentity = (az aks show --resource-group $resourceGroupName --name $clusterName --query "identity" -o tsv)
    if ($managedIdentity) {
        Write-Host "Managed Identity is configured: $managedIdentity" -ForegroundColor Green
    } else {
        Write-Host "Managed Identity is not configured." -ForegroundColor Red
    }

    # 17. Check for Azure Security Center Integration
    $securityCenter = (az security pricing show --name 'default' --query "tier" -o tsv)
    if ($securityCenter -eq "Standard") {
        Write-Host "Azure Security Center integration is enabled with Standard tier." -ForegroundColor Green
    } else {
        Write-Host "Azure Security Center integration is not enabled with Standard tier." -ForegroundColor Red
    }

    # 18. Check for Cluster Autoscaler
    $autoscaler = (az aks show --resource-group $resourceGroupName --name $clusterName --query "agentPoolProfiles[].enableAutoScaling" -o tsv)
    if ($autoscaler -contains "true") {
        Write-Host "Cluster Autoscaler is enabled." -ForegroundColor Green
    } else {
        Write-Host "Cluster Autoscaler is not enabled." -ForegroundColor Red
    }

    # 19. Check for Azure Key Vault Integration
    $keyVaultIntegration = (az aks show --resource-group $resourceGroupName --name $clusterName --query "addonProfiles.azureKeyvaultSecretsProvider.enabled" -o tsv)
    if ($keyVaultIntegration -eq "true") {
        Write-Host "Azure Key Vault integration is enabled." -ForegroundColor Green
    } else {
        Write-Host "Azure Key Vault integration is not enabled." -ForegroundColor Red
    }

    Write-Host "Security check completed for AKS cluster: $clusterName" -ForegroundColor Cyan
}
