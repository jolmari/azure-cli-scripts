$subcriptionId = "<subscription-id>"
$policyDefinitionId = "<policy-definition-id>"

$subscriptionScope = "/subscriptions/$subcriptionId/"
$policyScope = "/providers/Microsoft.Authorization/policyDefinitions/$policyDefinitionId";

$assignment = az policy assignment list --scope $subscriptionScope --query "[?policyDefinitionId=='$policyScope']"  -o json | ConvertFrom-Json
$remediation = az policy remediation create --name "remediate-policy" --policy-assignment $assignment[0].name

Write-Output $remediation
