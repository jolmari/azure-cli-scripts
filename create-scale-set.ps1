$resourceGroupName = "vmscale-set-resourcegroup"
$sigName = "mySharedImageGallery"
$galleryImageDefinition = "myImageDefinition"
$scaleSetName = "vmss1"

# Get the id of the latest image version
$versionId = az sig image-version list `
    --resource-group $resourceGroupName `
    --gallery-name $sigName `
    --gallery-image-definition $galleryImageDefinition `
    --query [0].id

# Create scale set
az vmss create `
    --name $scaleSetName `
    --resource-group $resourceGroupName `
    --image $versionId `
    --instance-count 2 `
    --security-type TrustedLaunch
