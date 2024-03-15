$resourceGroupName = "vmscale-set-resourcegroup"
$location = "northeurope"
$sigName = "mySharedImageGallery"
$galleryImageDefinition = "myImageDefinition"

# List resource groups in location
az group list --query "[?location=='$location']" -o table

# List VMs in the resource group
az vm list --resource-group $resourceGroupName --show-details -o table

# Find out VM sizes in location
az vm list-sizes --location $location -o table

# List image versions in shared image gallery
az sig image-version list `
    --gallery-image-definition $galleryImageDefinition `
    --gallery-name $sigName `
    --resource-group $resourceGroupName `
    --output table