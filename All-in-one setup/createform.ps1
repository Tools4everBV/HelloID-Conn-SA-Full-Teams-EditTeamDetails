# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Teams") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> EntraIdCertificatePassword
$tmpName = @'
EntraIdCertificatePassword
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

#Global variable #2 >> EntraIdCertificateBase64String
$tmpName = @'
EntraIdCertificateBase64String
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

#Global variable #3 >> EntraIdTenantId
$tmpName = @'
EntraIdTenantId
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

#Global variable #4 >> EntraIdAppId
$tmpName = @'
EntraIdAppId
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});


#make sure write-information logging is visual
$InformationPreference = "continue"

# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}

# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}

# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  

# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}

function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )

    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid

            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}

function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task

            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid

            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }

    $returnObject.Value = $taskGuid
}

function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter()][String][AllowEmptyString()]$DatasourceRunInCloud,
        [parameter(Mandatory)][Ref]$returnObject
    )

    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
                runInCloud         = $DatasourceRunInCloud;
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }

    $returnObject.Value = $datasourceGuid
}

function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }

    $returnObject.Value = $formGuid
}


function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][Array][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter()][String][AllowEmptyString()]$task,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }
            if(-not[String]::IsNullOrEmpty($AccessGroups)) { 
                $body += @{
                    accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                }
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true

            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }

    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}


<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "teams-edit-team-details | Teams-Lookup-A-Team-By-Name" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Teams-Lookup-A-Team-By-Name
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form:
$searchValue = $datasource.searchValue

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    if ([string]::IsNullOrEmpty($searchValue)) {
        return
    }

    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization      = "Bearer $entraToken"
        'Content-Type'     = "application/json"
        Accept             = "application/json"
        "ConsistencyLevel" = "eventual"
    }

    $searchQuery = '"displayName:{0}" OR "mailNickname:{0}"' -f $searchValue
    $actionMessage = "searching for Teams-enabled EntraID groups with query: $searchQuery"
    Write-Information $actionMessage

    $searchUri = "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$search=$searchQuery&`$top=999"
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teams = @($teamsResponse.value)

    while (-not [string]::IsNullOrEmpty($teamsResponse.'@odata.nextLink')) {
        $teamsResponse = Invoke-RestMethod -Uri $teamsResponse.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
        $teams += $teamsResponse.value
    }

    $teams = $teams | Sort-Object -Property DisplayName
    Write-Information -Message "Result count: $(@($teams).Count)"

    foreach ($team in $teams) {
        $returnObject = @{
            DisplayName  = $team.DisplayName
            Description  = $team.Description
            MailNickName = $team.MailNickName
            Mailaddress  = $team.Mail
            Visibility   = $team.Visibility
            GroupId      = $team.Id
        }
        Write-Output $returnObject
    }
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"Visibility","type":0},{"key":"GroupId","type":0},{"key":"Mailaddress","type":0},{"key":"MailNickName","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"searchValue","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
teams-edit-team-details | Teams-Lookup-A-Team-By-Name
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "teams-edit-team-details | Teams-Lookup-A-Team-By-Name" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_18 = [PSCustomObject]@{} 
$dataSourceGuid_18_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_18_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_18) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_16 = [PSCustomObject]@{} 
$dataSourceGuid_16_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_16_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_16) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_15 = [PSCustomObject]@{} 
$dataSourceGuid_15_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_15_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_15) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_3 = [PSCustomObject]@{} 
$dataSourceGuid_3_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_3_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_3) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_5 = [PSCustomObject]@{} 
$dataSourceGuid_5_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_5_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_5) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_11 = [PSCustomObject]@{} 
$dataSourceGuid_11_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_11_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_11) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_13 = [PSCustomObject]@{} 
$dataSourceGuid_13_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_13_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_13) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_12 = [PSCustomObject]@{} 
$dataSourceGuid_12_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_12_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_12) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_10 = [PSCustomObject]@{} 
$dataSourceGuid_10_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_10_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_10) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_4 = [PSCustomObject]@{} 
$dataSourceGuid_4_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_4_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_4) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_6 = [PSCustomObject]@{} 
$dataSourceGuid_6_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_6_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_6) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_17 = [PSCustomObject]@{} 
$dataSourceGuid_17_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_17_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_17) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_7 = [PSCustomObject]@{} 
$dataSourceGuid_7_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_7_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_7) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_9 = [PSCustomObject]@{} 
$dataSourceGuid_9_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_9_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_9) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_14 = [PSCustomObject]@{} 
$dataSourceGuid_14_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_14_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_14) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>

<# Begin: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
$tmpPsScript = @'
#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Parameters
# Date: 03-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

#endregion init

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [Ordered]@{
            'iss' = "$entraidappid"
            'sub' = "$entraidappid"
            'aud' = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $entraidappid
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions

try {
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "getting Team settings details for Team ID [$groupId]"
    Write-Information $actionMessage

    $teamsResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop
    $teamsResponseBeta = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/teams/$groupId" -Method Get -Headers $authorization -Verbose:$false -ErrorAction Stop

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings

    $returnObject = @{
        m_allowCreatePrivateChannels        = $memberSettings.allowCreatePrivateChannels
        m_allowCreateUpdateChannels         = $memberSettings.allowCreateUpdateChannels
        m_allowDeleteChannels               = $memberSettings.allowDeleteChannels
        m_allowAddRemoveApps                = $memberSettings.allowAddRemoveApps
        m_allowCreateUpdateRemoveTabs       = $memberSettings.allowCreateUpdateRemoveTabs
        m_allowCreateUpdateRemoveConnectors = $memberSettings.allowCreateUpdateRemoveConnectors
        g_allowCreateUpdateChannels         = $guestSettings.allowCreateUpdateChannels
        g_allowDeleteChannels               = $guestSettings.allowDeleteChannels
        mes_allowUserEditMessages           = $messagingSettings.allowUserEditMessages
        mes_allowUserDeleteMessages         = $messagingSettings.allowUserDeleteMessages
        mes_allowOwnerDeleteMessages        = $messagingSettings.allowOwnerDeleteMessages
        mes_allowTeamMentions               = $messagingSettings.allowTeamMentions
        mes_allowChannelMentions            = $messagingSettings.allowChannelMentions
        f_allowGiphy                        = $funSettings.allowGiphy
        f_giphyContentRating                = $funSettings.giphyContentRating
        f_allowStickersAndMemes             = $funSettings.allowStickersAndMemes
        f_allowCustomMemes                  = $funSettings.allowCustomMemes
        b_showInTeamsSearchAndSuggestions   = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    Write-Error $auditMessage
}

'@ 
$tmpModel = @'
[{"key":"mes_allowUserDeleteMessages","type":0},{"key":"g_allowCreateUpdateChannels","type":0},{"key":"f_giphyContentRating","type":0},{"key":"m_allowCreateUpdateRemoveTabs","type":0},{"key":"mes_allowOwnerDeleteMessages","type":0},{"key":"f_allowGiphy","type":0},{"key":"b_showInTeamsSearchAndSuggestions","type":0},{"key":"f_allowCustomMemes","type":0},{"key":"m_allowCreateUpdateChannels","type":0},{"key":"mes_allowUserEditMessages","type":0},{"key":"f_allowStickersAndMemes","type":0},{"key":"m_allowDeleteChannels","type":0},{"key":"g_allowDeleteChannels","type":0},{"key":"m_allowCreateUpdateRemoveConnectors","type":0},{"key":"m_allowCreatePrivateChannels","type":0},{"key":"mes_allowTeamMentions","type":0},{"key":"m_allowAddRemoveApps","type":0},{"key":"mes_allowChannelMentions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_8 = [PSCustomObject]@{} 
$dataSourceGuid_8_Name = @'
teams-edit-team-details | Get-Team-Parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_8_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "True" -returnObject ([Ref]$dataSourceGuid_8) 
<# End: DataSource "teams-edit-team-details | Get-Team-Parameters" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Teams - Edit Team Details" #>
$tmpSchema = @"
[{"label":"Select Team","fields":[{"key":"searchValue","templateOptions":{"label":"Search for displayname","required":true},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"teams","templateOptions":{"label":"Select team","required":true,"grid":{"columns":[{"headerName":"Display Name","field":"DisplayName"},{"headerName":"Description","field":"Description"},{"headerName":"Mail Nick Name","field":"MailNickName"},{"headerName":"Mailaddress","field":"Mailaddress"},{"headerName":"Visibility","field":"Visibility"},{"headerName":"Group Id","field":"GroupId"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"searchValue","otherFieldValue":{"otherFieldKey":"searchValue"}}]}},"useFilter":true,"useDefault":false,"allowCsvDownload":true},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"Edit Team Details","fields":[{"key":"AllowCreatePrivateChannels","templateOptions":{"label":"AllowCreatePrivateChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"m_allowCreatePrivateChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowCreateUpdateChannels","templateOptions":{"label":"AllowCreateUpdateChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"m_allowCreateUpdateChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowDeleteChannels","templateOptions":{"label":"AllowDeleteChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"m_allowDeleteChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_3","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowAddRemoveApps","templateOptions":{"label":"AllowAddRemoveApps","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"m_allowAddRemoveApps","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_4","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowCreateUpdateRemoveTabs","templateOptions":{"label":"AllowCreateUpdateRemoveTabs","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"m_allowCreateUpdateRemoveTabs","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_5","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowCreateUpdateRemoveConnectors","templateOptions":{"label":"AllowCreateUpdateRemoveConnectors","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"m_allowCreateUpdateRemoveConnectors","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_6","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowGuestCreateUpdateChannels","templateOptions":{"label":"AllowGuestCreateUpdateChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"g_allowCreateUpdateChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_7","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowGuestDeleteChannels","templateOptions":{"label":"AllowGuestDeleteChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"g_allowDeleteChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_8","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowUserEditMessages","templateOptions":{"label":"AllowUserEditMessages","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"mes_allowUserEditMessages","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_9","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowUserDeleteMessages","templateOptions":{"label":"AllowUserDeleteMessages","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"mes_allowUserDeleteMessages","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_10","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowOwnerDeleteMessages","templateOptions":{"label":"AllowOwnerDeleteMessages","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"mes_allowOwnerDeleteMessages","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_11","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowTeamMentions","templateOptions":{"label":"AllowTeamMentions","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"mes_allowTeamMentions","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_12","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowChannelMentions","templateOptions":{"label":"AllowChannelMentions","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"mes_allowChannelMentions","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_13","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowGiphy","templateOptions":{"label":"AllowGiphy","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"f_allowGiphy","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_14","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"GiphyContentRating","templateOptions":{"label":"GiphyContentRating","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"f_giphyContentRating","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_15","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowStickersAndMemes","templateOptions":{"label":"AllowStickersAndMemes","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"f_allowStickersAndMemes","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_16","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowCustomMemes","templateOptions":{"label":"AllowCustomMemes","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"f_allowCustomMemes","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_17","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"ShowInTeamsSearchAndSuggestions","templateOptions":{"label":"ShowInTeamsSearchAndSuggestions","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"b_showInTeamsSearchAndSuggestions","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_18","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Teams - Edit Team Details
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
if(-not[String]::IsNullOrEmpty($delegatedFormAccessGroupNames)){
    foreach($group in $delegatedFormAccessGroupNames) {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
            $delegatedFormAccessGroupGuid = $response.groupGuid
            $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
            
            Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
        } catch {
            Write-Error "HelloID (access)group '$group', message: $_"
        }
    }
    if($null -ne $delegatedFormAccessGroupGuids){
        $delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Depth 100 -Compress)
    }
}

$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $response = $response | Where-Object {$_.name.en -eq $category}
        
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body -Depth 100

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Depth 100 -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Teams - Edit Team Details
'@
$tmpTask = @'
{"name":"Teams - Edit Team Details","script":"#######################################################################\n# Template: HelloID SA Delegated form task\n# Name: Teams - Edit Team Details\n# Date: 03-04-2026\n#######################################################################\n\n# For basic information about delegated form tasks see:\n# https://docs.helloid.com/en/service-automation/delegated-forms/delegated-form-tasks.html\n\n# Service automation variables:\n# https://docs.helloid.com/en/service-automation/service-automation-variables.html\n\n#region init\n\n$VerbosePreference = \"SilentlyContinue\"\n$InformationPreference = \"Continue\"\n$WarningPreference = \"Continue\"\n\n# global variables (Automation --\u003e Variable libary):\n# Outcommented as these are set from Global Variables\n# $EntraIdTenantId = \"\"\n# $EntraIdAppId = \"\"\n# $EntraIdCertificateBase64String = \"\"\n# $EntraIdCertificatePassword = \"\"\n\n# variables configured in form\n$groupId = $form.teams.GroupId\n$displayName = $form.teams.DisplayName\n\n#endregion init\n\n#region functions\nfunction Resolve-MicrosoftGraphAPIError {\n    [CmdletBinding()]\n    param (\n        [Parameter(Mandatory)]\n        [object]\n        $ErrorObject\n    )\n    process {\n        $httpErrorObj = [PSCustomObject]@{\n            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber\n            Line             = $ErrorObject.InvocationInfo.Line\n            ErrorDetails     = $ErrorObject.Exception.Message\n            FriendlyMessage  = $ErrorObject.Exception.Message\n        }\n        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {\n            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message\n        }\n        elseif ($ErrorObject.Exception.GetType().FullName -eq \u0027System.Net.WebException\u0027) {\n            if ($null -ne $ErrorObject.Exception.Response) {\n                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()\n                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {\n                    $httpErrorObj.ErrorDetails = $streamReaderResponse\n                }\n            }\n        }\n        try {\n            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop)\n            if ($errorDetailsObject.error_description) {\n                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description\n            }\n            elseif ($errorDetailsObject.error.message) {\n                $httpErrorObj.FriendlyMessage = \"$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)\"\n            }\n            elseif ($errorDetailsObject.error.details.message) {\n                $httpErrorObj.FriendlyMessage = \"$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)\"\n            }\n            else {\n                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails\n            }\n        }\n        catch {\n            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails\n        }\n        Write-Output $httpErrorObj\n    }\n}\n\nfunction Get-MSEntraAccessToken {\n    [CmdletBinding()]\n    param(\n        [Parameter(Mandatory)]\n        $Certificate\n    )\n    try {\n        $derBytes = $Certificate.RawData\n        $sha256 = [System.Security.Cryptography.SHA256]::Create()\n        $hashBytes = $sha256.ComputeHash($derBytes)\n        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace(\u0027+\u0027, \u0027-\u0027).Replace(\u0027/\u0027, \u0027_\u0027).Replace(\u0027=\u0027, \u0027\u0027)\n\n        $header = @{\n            \u0027alg\u0027      = \u0027RS256\u0027\n            \u0027typ\u0027      = \u0027JWT\u0027\n            \u0027x5t#S256\u0027 = $base64Thumbprint\n        } | ConvertTo-Json\n        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))\n\n        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]\u00271970-01-01T00:00:00Z\u0027).ToUniversalTime()).TotalSeconds)\n\n        $payload = [Ordered]@{\n            \u0027iss\u0027 = \"$entraidappid\"\n            \u0027sub\u0027 = \"$entraidappid\"\n            \u0027aud\u0027 = \"https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token\"\n            \u0027exp\u0027 = ($currentUnixTimestamp + 3600)\n            \u0027nbf\u0027 = ($currentUnixTimestamp - 300)\n            \u0027iat\u0027 = $currentUnixTimestamp\n            \u0027jti\u0027 = [Guid]::NewGuid().ToString()\n        } | ConvertTo-Json\n        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace(\u0027+\u0027, \u0027-\u0027).Replace(\u0027/\u0027, \u0027_\u0027).Replace(\u0027=\u0027, \u0027\u0027)\n\n        $rsaPrivate = $Certificate.PrivateKey\n        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()\n        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))\n\n        $signatureInput = \"$base64Header.$base64Payload\"\n        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), \u0027SHA256\u0027)\n        $base64Signature = [System.Convert]::ToBase64String($signature).Replace(\u0027+\u0027, \u0027-\u0027).Replace(\u0027/\u0027, \u0027_\u0027).Replace(\u0027=\u0027, \u0027\u0027)\n\n        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {\n            throw \"The certificate does not have a private key.\"\n        }\n\n        $jwtToken = \"$($base64Header).$($base64Payload).$($base64Signature)\"\n\n        $createEntraAccessTokenBody = @{\n            grant_type            = \u0027client_credentials\u0027\n            client_id             = $entraidappid\n            client_assertion_type = \u0027urn:ietf:params:oauth:client-assertion-type:jwt-bearer\u0027\n            client_assertion      = $jwtToken\n            resource              = \u0027https://graph.microsoft.com\u0027\n        }\n\n        $createEntraAccessTokenSplatParams = @{\n            Uri         = \"https://login.microsoftonline.com/$EntraIdTenantId/oauth2/token\"\n            Body        = $createEntraAccessTokenBody\n            Method      = \u0027POST\u0027\n            ContentType = \u0027application/x-www-form-urlencoded\u0027\n            Verbose     = $false\n            ErrorAction = \u0027Stop\u0027\n        }\n\n        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams\n        Write-Output $createEntraAccessTokenResponse.access_token\n    }\n    catch {\n        $PSCmdlet.ThrowTerminatingError($_)\n    }\n}\n\nfunction Get-MSEntraCertificate {\n    [CmdletBinding()]\n    param()\n    try {\n        $rawCertificate = [system.convert]::FromBase64String($EntraIdCertificateBase64String)\n        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraIdCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)\n        Write-Output $certificate\n    }\n    catch {\n        $PSCmdlet.ThrowTerminatingError($_)\n    }\n}\n\n#endregion functions\n\ntry {\n    if ($form.giphyContentRating -in @($true, \"true\", \"Strict\")) {\n        $giphyContentRating = \"Strict\"\n    }\n    else {\n        $giphyContentRating = \"Moderate\"\n    }\n\n    $actionMessage = \"authenticating to Microsoft Graph\"\n    Write-Verbose \u0027connecting to MS-Entra\u0027\n    $certificate = Get-MSEntraCertificate\n    $entraToken = Get-MSEntraAccessToken -Certificate $certificate\n\n    $authorization = @{\n        Authorization  = \"Bearer $entraToken\"\n        \u0027Content-Type\u0027 = \"application/json\"\n        Accept         = \"application/json\"\n    }\n\n    $actionMessage = \"updating team settings for Team [$displayName] with ID [$groupId]\"\n    $teamBody = @{\n        memberSettings    = @{\n            allowCreatePrivateChannels        = [bool]$form.AllowCreatePrivateChannels\n            allowCreateUpdateChannels         = [bool]$form.AllowCreateUpdateChannels\n            allowDeleteChannels               = [bool]$form.AllowDeleteChannels\n            allowAddRemoveApps                = [bool]$form.AllowAddRemoveApps\n            allowCreateUpdateRemoveTabs       = [bool]$form.AllowCreateUpdateRemoveTabs\n            allowCreateUpdateRemoveConnectors = [bool]$form.AllowCreateUpdateRemoveConnectors\n        }\n        guestSettings     = @{\n            allowCreateUpdateChannels = [bool]$form.AllowGuestCreateUpdateChannels\n            allowDeleteChannels       = [bool]$form.AllowGuestDeleteChannels\n        }\n        messagingSettings = @{\n            allowUserEditMessages    = [bool]$form.AllowUserEditMessages\n            allowUserDeleteMessages  = [bool]$form.AllowUserDeleteMessages\n            allowOwnerDeleteMessages = [bool]$form.AllowOwnerDeleteMessages\n            allowTeamMentions        = [bool]$form.AllowTeamMentions\n            allowChannelMentions     = [bool]$form.AllowChannelMentions\n        }\n        funSettings       = @{\n            allowGiphy            = [bool]$form.AllowGiphy\n            giphyContentRating    = $giphyContentRating\n            allowStickersAndMemes = [bool]$form.AllowStickersAndMemes\n            allowCustomMemes      = [bool]$form.AllowCustomMemes\n        }\n    }\n\n    $updateTeamSplatParams = @{\n        Uri         = \"https://graph.microsoft.com/v1.0/teams/$groupId\"\n        Body        = ($teamBody | ConvertTo-Json -Depth 10)\n        Headers     = $authorization\n        Method      = \u0027PATCH\u0027\n        ContentType = \u0027application/json\u0027\n        Verbose     = $false\n        ErrorAction = \u0027Stop\u0027\n    }\n    $null = Invoke-RestMethod @updateTeamSplatParams\n\n    $actionMessage = \"updating team beta discovery settings for Team [$displayName] with ID [$groupId]\"\n    $teamBetaBody = @{\n        discoverySettings = @{\n            showInTeamsSearchAndSuggestions = [bool]$form.ShowInTeamsSearchAndSuggestions\n        }\n    }\n\n    $updateBetaTeamSplatParams = @{\n        Uri         = \"https://graph.microsoft.com/beta/teams/$groupId\"\n        Body        = ($teamBetaBody | ConvertTo-Json -Depth 10)\n        Headers     = $authorization\n        Method      = \u0027PATCH\u0027\n        ContentType = \u0027application/json\u0027\n        Verbose     = $false\n        ErrorAction = \u0027Stop\u0027\n    }\n    $null = Invoke-RestMethod @updateBetaTeamSplatParams\n\n    Write-Information \"Successfully updated Team [$displayName] with ID [$groupId].\"\n    $Log = @{\n        Action            = \"UpdateResource\"\n        System            = \"MicrosoftTeams\"\n        Message           = \"Successfully updated Team [$displayName] with ID [$groupId].\"\n        IsError           = $false\n        TargetDisplayName = $displayName\n        TargetIdentifier  = $groupId\n    }\n    Write-Information -Tags \"Audit\" -MessageData $log\n}\ncatch {\n    $ex = $PSItem\n    if ($($ex.Exception.GetType().FullName -eq \u0027Microsoft.PowerShell.Commands.HttpResponseException\u0027) -or\n        $($ex.Exception.GetType().FullName -eq \u0027System.Net.WebException\u0027)) {\n        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex\n        $auditMessage = \"Error $($actionMessage). Error: $($errorObj.FriendlyMessage)\"\n        $warningMessage = \"Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)\"\n    }\n    else {\n        $auditMessage = \"Error $($actionMessage). Error: $($ex.Exception.Message)\"\n        $warningMessage = \"Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)\"\n    }\n\n    $Log = @{\n        Action            = \"UpdateResource\"\n        System            = \"MicrosoftTeams\"\n        Message           = $auditMessage\n        IsError           = $true\n        TargetDisplayName = $displayName\n        TargetIdentifier  = $groupId\n    }\n    Write-Information -Tags \"Audit\" -MessageData $log\n    Write-Warning $warningMessage\n    Write-Error $auditMessage\n}\n","runInCloud":true}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-pencil-square" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

