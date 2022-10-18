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

#Global variable #1 >> AADAppId
$tmpName = @'
AADAppId
'@ 
$tmpValue = ""
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> AADAppSecret
$tmpName = @'
AADAppSecret
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #3 >> AADtenantID
$tmpName = @'
AADtenantID
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


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
<# Begin: DataSource "Teams-generate-table-wildcard" #>
$tmpPsScript = @'
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    $searchValue = $datasource.searchValue
    $searchQuery = "*$searchValue*"
      
      
    if([String]::IsNullOrEmpty($searchValue) -eq $true){
        return
    }else{
        Write-Information -Message "Generating Microsoft Graph API Access Token user.."

        $baseUri = "https://login.microsoftonline.com/"
        $authUri = $baseUri + "$AADTenantID/oauth2/token"

        $body = @{
            grant_type      = "client_credentials"
            client_id       = "$AADAppId"
            client_secret   = "$AADAppSecret"
            resource        = "https://graph.microsoft.com"
        }
 
        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token;

        Write-Information -Message "Searching for: $searchQuery"
        #Add the authorization header to the request
        $authorization = @{
            Authorization = "Bearer $accesstoken";
            'Content-Type' = "application/json";
            Accept = "application/json";
        }
 
        $baseSearchUri = "https://graph.microsoft.com/"
        $searchUri = $baseSearchUri + "v1.0/groups" + "?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')"                        
        $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

        $teams = foreach($teamObject in $teamsResponse.value){
            if($teamObject.displayName -like $searchQuery -or $teamObject.mailNickName -like $searchQuery){
                $teamObject
            }
        }

        $teams = $teams | Sort-Object -Property DisplayName
        $resultCount = @($teams).Count
        Write-Information -Message "Result count: $resultCount"
         
        if($resultCount -gt 0){
            foreach($team in $teams){
                $channelUri = $baseSearchUri + "v1.0/teams" + "/$($team.id)/channels"                
                $channel = Invoke-RestMethod -Uri $channelUri -Method Get -Headers $authorization -Verbose:$false
                $returnObject = @{DisplayName=$team.DisplayName; Description=$team.Description; MailNickName=$team.MailNickName; Mailaddress=$team.Mail; Visibility=$team.Visibility; GroupId=$team.Id}
                Write-Output $returnObject
            }
        } else {
            return
        }
    }
} catch {
    
    Write-Error -Message ("Error searching for Teams-enabled AzureAD groups. Error: $($_.Exception.Message)" + $errorDetailsMessage)
    Write-Warning -Message "Error searching for Teams-enabled AzureAD groups"
     
    return
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
Teams-generate-table-wildcard
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "Teams-generate-table-wildcard" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_18_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_18) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_16_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_16) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_15_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_15) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_3_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_3) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_5_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_5) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_11_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_11) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_13_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_13) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_12_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_12) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_10_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_10) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_4_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_4) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_6_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_6) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_17_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_17) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_7_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_7) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_9_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_9) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_14_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_14) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>

<# Begin: DataSource "Teams-edit-team-details-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId

try {
    Write-Information -Message "Generating Microsoft Graph API Access Token user.."

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/teams" + "/$groupId"        
    
    Write-Information -Message "Getting Team details."
    $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

    $memberSettings = $teamsResponse.memberSettings
    $messagingSettings = $teamsResponse.messagingSettings
    $funSettings = $teamsResponse.funSettings
    $guestSettings = $teamsResponse.guestSettings

    $betaUri = $baseSearchUri + "beta/teams" + "/$groupId"
    $teamsResponseBeta = Invoke-RestMethod -Uri $betaUri -Method Get -Headers $authorization -Verbose:$false          
    $teamDiscoverySettings = $teamsResponseBeta.discoverySettings
    
    $returnObject = @{
        m_allowCreatePrivateChannels=$memberSettings.allowCreatePrivateChannels;
        m_allowCreateUpdateChannels=$memberSettings.allowCreateUpdateChannels;
        m_allowDeleteChannels=$memberSettings.allowDeleteChannels;
        m_allowAddRemoveApps=$memberSettings.allowAddRemoveApps;
        m_allowCreateUpdateRemoveTabs=$memberSettings.allowCreateUpdateRemoveTabs;
        m_allowCreateUpdateRemoveConnectors=$memberSettings.allowCreateUpdateRemoveConnectors;
        g_allowCreateUpdateChannels=$guestSettings.allowCreateUpdateChannels;
        g_allowDeleteChannels=$guestSettings.allowDeleteChannels;
        mes_allowUserEditMessages=$messagingSettings.allowUserEditMessages;
        mes_allowUserDeleteMessages=$messagingSettings.allowUserDeleteMessages;
        mes_allowOwnerDeleteMessages=$messagingSettings.allowOwnerDeleteMessages;
        mes_allowTeamMentions=$messagingSettings.allowTeamMentions;
        mes_allowChannelMentions=$messagingSettings.allowChannelMentions;
        f_allowGiphy=$funSettings.allowGiphy;
        f_giphyContentRating=$funSettings.giphyContentRating;
        f_allowStickersAndMemes=$funSettings.allowStickersAndMemes;
        f_allowCustomMemes=$funSettings.allowCustomMemes;
        b_showInTeamsSearchAndSuggestions = $teamDiscoverySettings.showInTeamsSearchAndSuggestions
    }    
    Write-Output $returnObject        
    
}
catch
{
    Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    Write-Warning -Message "Error getting Team Details"
    return
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
Teams-edit-team-details-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_8_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_8) 
<# End: DataSource "Teams-edit-team-details-get-team-parameters" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Teams - Edit Team Details" #>
$tmpSchema = @"
[{"label":"Select Team","fields":[{"key":"searchValue","templateOptions":{"label":"Search for displayname","required":true},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"teams","templateOptions":{"label":"Select team","required":true,"grid":{"columns":[{"headerName":"Display Name","field":"DisplayName"},{"headerName":"Description","field":"Description"},{"headerName":"Mail Nick Name","field":"MailNickName"},{"headerName":"Mailaddress","field":"Mailaddress"},{"headerName":"Visibility","field":"Visibility"},{"headerName":"Group Id","field":"GroupId"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"searchValue","otherFieldValue":{"otherFieldKey":"searchValue"}}]}},"useFilter":true,"useDefault":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"Edit Team Details","fields":[{"key":"AllowCreatePrivateChannels","templateOptions":{"label":"AllowCreatePrivateChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"m_allowCreatePrivateChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowCreateUpdateChannels","templateOptions":{"label":"AllowCreateUpdateChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"m_allowCreateUpdateChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowDeleteChannels","templateOptions":{"label":"AllowDeleteChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"m_allowDeleteChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_3","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowAddRemoveApps","templateOptions":{"label":"AllowAddRemoveApps","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"m_allowAddRemoveApps","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_4","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowCreateUpdateRemoveTabs","templateOptions":{"label":"AllowCreateUpdateRemoveTabs","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"m_allowCreateUpdateRemoveTabs","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_5","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowCreateUpdateRemoveConnectors","templateOptions":{"label":"AllowCreateUpdateRemoveConnectors","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"m_allowCreateUpdateRemoveConnectors","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_6","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowGuestCreateUpdateChannels","templateOptions":{"label":"AllowGuestCreateUpdateChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"g_allowCreateUpdateChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_7","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowGuestDeleteChannels","templateOptions":{"label":"AllowGuestDeleteChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"g_allowDeleteChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_8","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowUserEditMessages","templateOptions":{"label":"AllowUserEditMessages","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"mes_allowUserEditMessages","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_9","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowUserDeleteMessages","templateOptions":{"label":"AllowUserDeleteMessages","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"mes_allowUserDeleteMessages","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_10","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowOwnerDeleteMessages","templateOptions":{"label":"AllowOwnerDeleteMessages","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"mes_allowOwnerDeleteMessages","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_11","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowTeamMentions","templateOptions":{"label":"AllowTeamMentions","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"mes_allowTeamMentions","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_12","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowChannelMentions","templateOptions":{"label":"AllowChannelMentions","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"mes_allowChannelMentions","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_13","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowGiphy","templateOptions":{"label":"AllowGiphy","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"f_allowGiphy","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_14","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"GiphyContentRating","templateOptions":{"label":"GiphyContentRating","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"f_giphyContentRating","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_15","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowStickersAndMemes","templateOptions":{"label":"AllowStickersAndMemes","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"f_allowStickersAndMemes","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_16","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowCustomMemes","templateOptions":{"label":"AllowCustomMemes","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"f_allowCustomMemes","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_17","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"ShowInTeamsSearchAndSuggestions","templateOptions":{"label":"ShowInTeamsSearchAndSuggestions","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"b_showInTeamsSearchAndSuggestions","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_18","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
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
{"name":"Teams - Edit Team Details","script":"# Set TLS to accept TLS, TLS 1.1 and TLS 1.2\r\n[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12\r\n\r\n$baseGraphUri = \"https://graph.microsoft.com/\"\r\n\r\n$VerbosePreference = \"SilentlyContinue\"\r\n$InformationPreference = \"Continue\"\r\n$WarningPreference = \"Continue\"\r\n\r\n# variables configured in form\r\n$groupId     =   $form.teams.GroupId\r\n$displayName = $form.teams.DisplayName\r\n\r\nif ($form.giphyContentRating -eq \"true\") { $giphyContentRating = \"Strict\" } else { $giphyContentRating = \"Moderate\" }\r\n\r\n# Create authorization token and add to headers\r\ntry {\r\n    Write-Information \"Generating Microsoft Graph API Access Token\"\r\n\r\n    $baseUri = \"https://login.microsoftonline.com/\"\r\n    $authUri = $baseUri + \"$AADTenantID/oauth2/token\"\r\n\r\n    $body = @{\r\n        grant_type    = \"client_credentials\"\r\n        client_id     = \"$AADAppId\"\r\n        client_secret = \"$AADAppSecret\"\r\n        resource      = \"https://graph.microsoft.com\"\r\n    }\r\n\r\n    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType \u0027application/x-www-form-urlencoded\u0027\r\n    $accessToken = $Response.access_token;\r\n\r\n    #Add the authorization header to the request\r\n    $authorization = @{\r\n        Authorization  = \"Bearer $accesstoken\";\r\n        \u0027Content-Type\u0027 = \"application/json\";\r\n        Accept         = \"application/json\";\r\n    }\r\n}\r\ncatch {\r\n    throw \"Could not generate Microsoft Graph API Access Token. Error: $($_.Exception.Message)\"    \r\n}\r\n\r\n\r\ntry {\r\n\t$updateTeamUri = $baseGraphUri + \"v1.0/teams/$groupId\"\r\n\r\n    $teambody = \r\n        @\"\r\n    {\r\n        \"memberSettings\": {\r\n            \"allowCreatePrivateChannels\" : \"$($form.AllowCreatePrivateChannels)\",\r\n            \"allowCreateUpdateChannels\": \"$($form.AllowCreateUpdateChannels)\",\r\n            \"allowDeleteChannels\": \"$($form.AllowDeleteChannels)\",\r\n            \"allowAddRemoveApps\": \"$($form.AllowAddRemoveApps)\",\r\n            \"allowCreateUpdateRemoveTabs\": \"$($form.AllowCreateUpdateRemoveTabs)\",\r\n            \"allowCreateUpdateRemoveConnectors\": \"$($form.AllowCreateUpdateRemoveConnectors)\"\r\n        },\r\n        \"guestSettings\": {\r\n            \"allowCreateUpdateChannels\": \"$($form.AllowGuestCreateUpdateChannels)\",\r\n            \"allowDeleteChannels\": \"$($form.AllowGuestDeleteChannels)\"\r\n        },\r\n        \"messagingSettings\": {\r\n            \"allowUserEditMessages\": \"$($form.AllowUserEditMessages)\",\r\n            \"allowUserDeleteMessages\": \"$($form.AllowUserDeleteMessages)\",\r\n            \"allowOwnerDeleteMessages\": \"$($form.AllowOwnerDeleteMessages)\",\r\n            \"allowTeamMentions\": \"$($form.AllowTeamMentions)\",\r\n            \"allowChannelMentions\": \"$($form.AllowChannelMentions)\"\r\n        },\r\n        \"funSettings\": {\r\n            \"allowGiphy\": \"$($form.AllowGiphy)\",\r\n            \"giphyContentRating\": \"$giphyContentRating\",\r\n            \"allowStickersAndMemes\": \"$($form.AllowStickersAndMemes)\",\r\n            \"allowCustomMemes\": \"$($form.AllowCustomMemes)\"\r\n        }\r\n    }\r\n\"@\r\n    \r\n    $updateteam = Invoke-RestMethod -Method PATCH -Uri $updateTeamUri -Body $teambody -Headers $authorization \r\n\r\n    Write-Information \"Successfully updated Team [$displayName] with id [$groupId].\"\r\n        $Log = @{\r\n            Action            = \"UpdateResource\" # optional. ENUM (undefined = default) \r\n            System            = \"AzureActiveDirectory\" # optional (free format text) \r\n            Message           = \"Successfully updated Team [$displayName] with id [$groupId].\" # required (free format text) \r\n            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $displayName # optional (free format text)\r\n            TargetIdentifier  = $groupId # optional (free format text)\r\n        }\r\n        #send result back  \r\n        Write-Information -Tags \"Audit\" -MessageData $log\r\n}\r\ncatch\r\n{\t\r\n    Write-Error \"Failed to update Team [$displayName]. Error: $($_.Exception.Message)\"\r\n    $Log = @{\r\n        Action            = \"UpdateResource\" # optional. ENUM (undefined = default) \r\n        System            = \"AzureActiveDirectory\" # optional (free format text) \r\n        Message           = \"Failed to update team [$displayName] with id [$groupId].\" # required (free format text) \r\n        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $displayName # optional (free format text)\r\n        TargetIdentifier  = $groupId # optional (free format text)\r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n}\r\n\r\ntry {\r\n\t$updateBetaTeamUri = $baseGraphUri + \"beta/teams/$groupId\"\r\n\r\n    $teambetabody = \r\n        @\"\r\n    {\r\n        \"discoverySettings\": {\r\n            \"showInTeamsSearchAndSuggestions\" : \"$($form.ShowInTeamsSearchAndSuggestions)\"\r\n        }\r\n    }\r\n\"@\r\n\r\n    $updatebetateam = Invoke-RestMethod -Method PATCH -Uri $updateBetaTeamUri -Body $teambetabody -Headers $authorization \r\n\r\n    Write-Information \"Successfully updated betasettings Team [$displayName] with id [$groupId].\"\r\n        $Log = @{\r\n            Action            = \"UpdateResource\" # optional. ENUM (undefined = default) \r\n            System            = \"AzureActiveDirectory\" # optional (free format text) \r\n            Message           = \"Successfully updated betasettings Team [$displayName] with id [$groupId].\" # required (free format text) \r\n            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $displayName # optional (free format text)\r\n            TargetIdentifier  = $groupId # optional (free format text)\r\n        }\r\n        #send result back  \r\n        Write-Information -Tags \"Audit\" -MessageData $log\r\n}\r\ncatch\r\n{\t\r\n     Write-Error \"Failed to update betasettings Team [$displayName]. Error: $($_.Exception.Message)\"\r\n    $Log = @{\r\n        Action            = \"UpdateResource\" # optional. ENUM (undefined = default) \r\n        System            = \"AzureActiveDirectory\" # optional (free format text) \r\n        Message           = \"Failed to update betasettings team [$displayName] with id [$groupId].\" # required (free format text) \r\n        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n        TargetDisplayName = $displayName # optional (free format text)\r\n        TargetIdentifier  = $groupId # optional (free format text)\r\n    }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n}","runInCloud":false}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-pencil-square" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

