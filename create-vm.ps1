$resourceGroupName = "vmscale-set-resourcegroup"
$location = "northeurope"
$vmName = "myvm"
$size = "Standard_DS1_v2"
$image = "Win2019Datacenter"
$nsgRule = "RDP"
$authenticationType = "password"

# Vm credentials
$adminUser = "azure"
$adminPassword = $args[0]

# Create a resource group
az group create --name $resourceGroupName --location $location

# Create VM with RDP port open
az vm create `
    --name $vmName `
    --resource-group $resourceGroupName `
    --location $location `
    --size $size `
    --image $image `
    --nsg-rule $nsgRule `
    --admin-username $adminUser `
    --admin-password $adminPassword `
    --authentication-type $authenticationType `
    --public-ip-sku standard `
    --output table

# Generalize the VM to proceed. Connect to RDP with <vmname>\azure and <adminPassword>.
# https://learn.microsoft.com/en-us/azure/virtual-machines/generalize#windows

# Generalize the VM service
# az vm generalize --resource-group $resourceGroupName --name $vmName