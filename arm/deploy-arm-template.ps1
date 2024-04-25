$resourceGroupName = "az-104-template"
az deployment group create --resource-group $resourceGroupName --template-file .\files\template.json --parameters .\files\template.parameters.json