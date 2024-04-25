$resourceGroupName = "vmscale-set-resourcegroup"
$location = "northeurope"
$vmName = "myvm"
$sigName = "mySharedImageGallery"

# Image definition
$galleryImageDefinition = "myImageDefinition"
$publisher = "myPublisher"
$offer = "myOffer"
$sku = "mySKU"

# Scale set 
$scaleSetName = "vmss1"

# Create shared image gallery & image of myvm
# https://learn.microsoft.com/en-us/cli/azure/sig?view=azure-cli-latest#az-sig-create
az sig create `
    --gallery-name $sigName `
    --resource-group $resourceGroupName `
    --location $location

$vmId = az vm get-instance-view `
    --resource-group $resourceGroupName `
    --name $vmName `
    --query id

az sig image-definition create `
    --resource-group $resourceGroupName `
    --gallery-name $sigName `
    --gallery-image-definition $galleryImageDefinition `
    --publisher $publisher `
    --offer $offer `
    --sku $sku `
    --os-type Windows `
    --os-state generalized `
    --hyper-v-generation V2 `
    --features SecurityType=TrustedLaunch

# Create image version
$versionId = az sig image-version create `
    --resource-group $resourceGroupName `
    --gallery-name $sigName `
    --gallery-image-definition $galleryImageDefinition `
    --gallery-image-version 1.0.0 `
    --replica-count 1 `
    --managed-image $vmId `
    --query id

# Create scale set
az vmss create `
    --name $scaleSetName `
    --resource-group $resourceGroupName `
    --image $versionId `
    --instance-count 2
