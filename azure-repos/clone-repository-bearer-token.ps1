$organizaationName = "contoso"
$projectName = "myproject"
$repositoryName = "myrepository"
$repositoryUrl = "https://dev.azure.com/$organizaationName/$projectName/_git/$repositoryName"

# Get a bearer token for querying the Azure DevOps repository
# https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/service-principal-managed-identity?view=azure-devops#q-can-i-use-a-service-principal-or-managed-identity-with-azure-cli
$azureDevOpsResourceId = "499b84ac-1321-427f-aa17-267ca6975798"
$bearerToken = az account get-access-token --resource $azureDevOpsResourceId --query "accessToken" --output tsv

# Clone the Azure DevOps repository
git -c http.extraheader="Authorization: Bearer $bearerToken" clone $repositoryUrl