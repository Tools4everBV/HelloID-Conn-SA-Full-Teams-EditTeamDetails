# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Teams") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> TeamsAdminUser
$tmpName = @'
TeamsAdminUser
'@ 
$tmpValue = @'
ramon@schoulens.onmicrosoft.com
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> TeamsAdminPWD
$tmpName = @'
TeamsAdminPWD
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
            $body = ConvertTo-Json -InputObject $body
    
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
            $body = ConvertTo-Json -InputObject $body
    
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
            $body = ConvertTo-Json -InputObject $body
      
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
        [parameter()][String][AllowEmptyString()]$AccessGroups,
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
                accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }    
            $body = ConvertTo-Json -InputObject $body
    
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
<# Begin: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $formInput.selectedGroup.GroupId

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
        $teams = Get-Team -GroupId $groupId
        
        if(@($teams).Count -eq 1){
        #  foreach($tmp in $teams.psObject.properties)
         foreach($team in $teams)
            {
                $returnObject = $team
                Write-Output $returnObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    }
}
'@ 
$tmpModel = @'
[{"key":"GroupId","type":0},{"key":"InternalId","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0},{"key":"Visibility","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0},{"key":"AllowGiphy","type":0},{"key":"GiphyContentRating","type":0},{"key":"AllowStickersAndMemes","type":0},{"key":"AllowCustomMemes","type":0},{"key":"AllowGuestCreateUpdateChannels","type":0},{"key":"AllowGuestDeleteChannels","type":0},{"key":"AllowCreateUpdateChannels","type":0},{"key":"AllowCreatePrivateChannels","type":0},{"key":"AllowDeleteChannels","type":0},{"key":"AllowAddRemoveApps","type":0},{"key":"AllowCreateUpdateRemoveTabs","type":0},{"key":"AllowCreateUpdateRemoveConnectors","type":0},{"key":"AllowUserEditMessages","type":0},{"key":"AllowUserDeleteMessages","type":0},{"key":"AllowOwnerDeleteMessages","type":0},{"key":"AllowTeamMentions","type":0},{"key":"AllowChannelMentions","type":0},{"key":"ShowInTeamsSearchAndSuggestions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_11 = [PSCustomObject]@{} 
$dataSourceGuid_11_Name = @'
Edit-Team-Details-Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_11_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_11) 
<# End: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>

<# Begin: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $formInput.selectedGroup.GroupId

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
        $teams = Get-Team -GroupId $groupId
        
        if(@($teams).Count -eq 1){
        #  foreach($tmp in $teams.psObject.properties)
         foreach($team in $teams)
            {
                $returnObject = $team
                Write-Output $returnObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    }
}
'@ 
$tmpModel = @'
[{"key":"GroupId","type":0},{"key":"InternalId","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0},{"key":"Visibility","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0},{"key":"AllowGiphy","type":0},{"key":"GiphyContentRating","type":0},{"key":"AllowStickersAndMemes","type":0},{"key":"AllowCustomMemes","type":0},{"key":"AllowGuestCreateUpdateChannels","type":0},{"key":"AllowGuestDeleteChannels","type":0},{"key":"AllowCreateUpdateChannels","type":0},{"key":"AllowCreatePrivateChannels","type":0},{"key":"AllowDeleteChannels","type":0},{"key":"AllowAddRemoveApps","type":0},{"key":"AllowCreateUpdateRemoveTabs","type":0},{"key":"AllowCreateUpdateRemoveConnectors","type":0},{"key":"AllowUserEditMessages","type":0},{"key":"AllowUserDeleteMessages","type":0},{"key":"AllowOwnerDeleteMessages","type":0},{"key":"AllowTeamMentions","type":0},{"key":"AllowChannelMentions","type":0},{"key":"ShowInTeamsSearchAndSuggestions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
Edit-Team-Details-Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>

<# Begin: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $formInput.selectedGroup.GroupId

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
        $teams = Get-Team -GroupId $groupId
        
        if(@($teams).Count -eq 1){
        #  foreach($tmp in $teams.psObject.properties)
         foreach($team in $teams)
            {
                $returnObject = $team
                Write-Output $returnObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    }
}
'@ 
$tmpModel = @'
[{"key":"GroupId","type":0},{"key":"InternalId","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0},{"key":"Visibility","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0},{"key":"AllowGiphy","type":0},{"key":"GiphyContentRating","type":0},{"key":"AllowStickersAndMemes","type":0},{"key":"AllowCustomMemes","type":0},{"key":"AllowGuestCreateUpdateChannels","type":0},{"key":"AllowGuestDeleteChannels","type":0},{"key":"AllowCreateUpdateChannels","type":0},{"key":"AllowCreatePrivateChannels","type":0},{"key":"AllowDeleteChannels","type":0},{"key":"AllowAddRemoveApps","type":0},{"key":"AllowCreateUpdateRemoveTabs","type":0},{"key":"AllowCreateUpdateRemoveConnectors","type":0},{"key":"AllowUserEditMessages","type":0},{"key":"AllowUserDeleteMessages","type":0},{"key":"AllowOwnerDeleteMessages","type":0},{"key":"AllowTeamMentions","type":0},{"key":"AllowChannelMentions","type":0},{"key":"ShowInTeamsSearchAndSuggestions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_7 = [PSCustomObject]@{} 
$dataSourceGuid_7_Name = @'
Edit-Team-Details-Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_7_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_7) 
<# End: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>

<# Begin: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $formInput.selectedGroup.GroupId

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
        $teams = Get-Team -GroupId $groupId
        
        if(@($teams).Count -eq 1){
        #  foreach($tmp in $teams.psObject.properties)
         foreach($team in $teams)
            {
                $returnObject = $team
                Write-Output $returnObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    }
}
'@ 
$tmpModel = @'
[{"key":"GroupId","type":0},{"key":"InternalId","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0},{"key":"Visibility","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0},{"key":"AllowGiphy","type":0},{"key":"GiphyContentRating","type":0},{"key":"AllowStickersAndMemes","type":0},{"key":"AllowCustomMemes","type":0},{"key":"AllowGuestCreateUpdateChannels","type":0},{"key":"AllowGuestDeleteChannels","type":0},{"key":"AllowCreateUpdateChannels","type":0},{"key":"AllowCreatePrivateChannels","type":0},{"key":"AllowDeleteChannels","type":0},{"key":"AllowAddRemoveApps","type":0},{"key":"AllowCreateUpdateRemoveTabs","type":0},{"key":"AllowCreateUpdateRemoveConnectors","type":0},{"key":"AllowUserEditMessages","type":0},{"key":"AllowUserDeleteMessages","type":0},{"key":"AllowOwnerDeleteMessages","type":0},{"key":"AllowTeamMentions","type":0},{"key":"AllowChannelMentions","type":0},{"key":"ShowInTeamsSearchAndSuggestions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_6 = [PSCustomObject]@{} 
$dataSourceGuid_6_Name = @'
Edit-Team-Details-Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_6_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_6) 
<# End: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>

<# Begin: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $formInput.selectedGroup.GroupId

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
        $teams = Get-Team -GroupId $groupId
        
        if(@($teams).Count -eq 1){
        #  foreach($tmp in $teams.psObject.properties)
         foreach($team in $teams)
            {
                $returnObject = $team
                Write-Output $returnObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    }
}
'@ 
$tmpModel = @'
[{"key":"GroupId","type":0},{"key":"InternalId","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0},{"key":"Visibility","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0},{"key":"AllowGiphy","type":0},{"key":"GiphyContentRating","type":0},{"key":"AllowStickersAndMemes","type":0},{"key":"AllowCustomMemes","type":0},{"key":"AllowGuestCreateUpdateChannels","type":0},{"key":"AllowGuestDeleteChannels","type":0},{"key":"AllowCreateUpdateChannels","type":0},{"key":"AllowCreatePrivateChannels","type":0},{"key":"AllowDeleteChannels","type":0},{"key":"AllowAddRemoveApps","type":0},{"key":"AllowCreateUpdateRemoveTabs","type":0},{"key":"AllowCreateUpdateRemoveConnectors","type":0},{"key":"AllowUserEditMessages","type":0},{"key":"AllowUserDeleteMessages","type":0},{"key":"AllowOwnerDeleteMessages","type":0},{"key":"AllowTeamMentions","type":0},{"key":"AllowChannelMentions","type":0},{"key":"ShowInTeamsSearchAndSuggestions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
Edit-Team-Details-Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>

<# Begin: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $formInput.selectedGroup.GroupId

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
        $teams = Get-Team -GroupId $groupId
        
        if(@($teams).Count -eq 1){
        #  foreach($tmp in $teams.psObject.properties)
         foreach($team in $teams)
            {
                $returnObject = $team
                Write-Output $returnObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    }
}
'@ 
$tmpModel = @'
[{"key":"GroupId","type":0},{"key":"InternalId","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0},{"key":"Visibility","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0},{"key":"AllowGiphy","type":0},{"key":"GiphyContentRating","type":0},{"key":"AllowStickersAndMemes","type":0},{"key":"AllowCustomMemes","type":0},{"key":"AllowGuestCreateUpdateChannels","type":0},{"key":"AllowGuestDeleteChannels","type":0},{"key":"AllowCreateUpdateChannels","type":0},{"key":"AllowCreatePrivateChannels","type":0},{"key":"AllowDeleteChannels","type":0},{"key":"AllowAddRemoveApps","type":0},{"key":"AllowCreateUpdateRemoveTabs","type":0},{"key":"AllowCreateUpdateRemoveConnectors","type":0},{"key":"AllowUserEditMessages","type":0},{"key":"AllowUserDeleteMessages","type":0},{"key":"AllowOwnerDeleteMessages","type":0},{"key":"AllowTeamMentions","type":0},{"key":"AllowChannelMentions","type":0},{"key":"ShowInTeamsSearchAndSuggestions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_4 = [PSCustomObject]@{} 
$dataSourceGuid_4_Name = @'
Edit-Team-Details-Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_4_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_4) 
<# End: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>

<# Begin: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $formInput.selectedGroup.GroupId

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
        $teams = Get-Team -GroupId $groupId
        
        if(@($teams).Count -eq 1){
        #  foreach($tmp in $teams.psObject.properties)
         foreach($team in $teams)
            {
                $returnObject = $team
                Write-Output $returnObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    }
}
'@ 
$tmpModel = @'
[{"key":"GroupId","type":0},{"key":"InternalId","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0},{"key":"Visibility","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0},{"key":"AllowGiphy","type":0},{"key":"GiphyContentRating","type":0},{"key":"AllowStickersAndMemes","type":0},{"key":"AllowCustomMemes","type":0},{"key":"AllowGuestCreateUpdateChannels","type":0},{"key":"AllowGuestDeleteChannels","type":0},{"key":"AllowCreateUpdateChannels","type":0},{"key":"AllowCreatePrivateChannels","type":0},{"key":"AllowDeleteChannels","type":0},{"key":"AllowAddRemoveApps","type":0},{"key":"AllowCreateUpdateRemoveTabs","type":0},{"key":"AllowCreateUpdateRemoveConnectors","type":0},{"key":"AllowUserEditMessages","type":0},{"key":"AllowUserDeleteMessages","type":0},{"key":"AllowOwnerDeleteMessages","type":0},{"key":"AllowTeamMentions","type":0},{"key":"AllowChannelMentions","type":0},{"key":"ShowInTeamsSearchAndSuggestions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_13 = [PSCustomObject]@{} 
$dataSourceGuid_13_Name = @'
Edit-Team-Details-Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_13_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_13) 
<# End: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>

<# Begin: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $formInput.selectedGroup.GroupId

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
        $teams = Get-Team -GroupId $groupId
        
        if(@($teams).Count -eq 1){
        #  foreach($tmp in $teams.psObject.properties)
         foreach($team in $teams)
            {
                $returnObject = $team
                Write-Output $returnObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    }
}
'@ 
$tmpModel = @'
[{"key":"GroupId","type":0},{"key":"InternalId","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0},{"key":"Visibility","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0},{"key":"AllowGiphy","type":0},{"key":"GiphyContentRating","type":0},{"key":"AllowStickersAndMemes","type":0},{"key":"AllowCustomMemes","type":0},{"key":"AllowGuestCreateUpdateChannels","type":0},{"key":"AllowGuestDeleteChannels","type":0},{"key":"AllowCreateUpdateChannels","type":0},{"key":"AllowCreatePrivateChannels","type":0},{"key":"AllowDeleteChannels","type":0},{"key":"AllowAddRemoveApps","type":0},{"key":"AllowCreateUpdateRemoveTabs","type":0},{"key":"AllowCreateUpdateRemoveConnectors","type":0},{"key":"AllowUserEditMessages","type":0},{"key":"AllowUserDeleteMessages","type":0},{"key":"AllowOwnerDeleteMessages","type":0},{"key":"AllowTeamMentions","type":0},{"key":"AllowChannelMentions","type":0},{"key":"ShowInTeamsSearchAndSuggestions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_16 = [PSCustomObject]@{} 
$dataSourceGuid_16_Name = @'
Edit-Team-Details-Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_16_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_16) 
<# End: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>

<# Begin: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $formInput.selectedGroup.GroupId

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
        $teams = Get-Team -GroupId $groupId
        
        if(@($teams).Count -eq 1){
        #  foreach($tmp in $teams.psObject.properties)
         foreach($team in $teams)
            {
                $returnObject = $team
                Write-Output $returnObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    }
}
'@ 
$tmpModel = @'
[{"key":"GroupId","type":0},{"key":"InternalId","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0},{"key":"Visibility","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0},{"key":"AllowGiphy","type":0},{"key":"GiphyContentRating","type":0},{"key":"AllowStickersAndMemes","type":0},{"key":"AllowCustomMemes","type":0},{"key":"AllowGuestCreateUpdateChannels","type":0},{"key":"AllowGuestDeleteChannels","type":0},{"key":"AllowCreateUpdateChannels","type":0},{"key":"AllowCreatePrivateChannels","type":0},{"key":"AllowDeleteChannels","type":0},{"key":"AllowAddRemoveApps","type":0},{"key":"AllowCreateUpdateRemoveTabs","type":0},{"key":"AllowCreateUpdateRemoveConnectors","type":0},{"key":"AllowUserEditMessages","type":0},{"key":"AllowUserDeleteMessages","type":0},{"key":"AllowOwnerDeleteMessages","type":0},{"key":"AllowTeamMentions","type":0},{"key":"AllowChannelMentions","type":0},{"key":"ShowInTeamsSearchAndSuggestions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_12 = [PSCustomObject]@{} 
$dataSourceGuid_12_Name = @'
Edit-Team-Details-Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_12_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_12) 
<# End: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>

<# Begin: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $formInput.selectedGroup.GroupId

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
        $teams = Get-Team -GroupId $groupId
        
        if(@($teams).Count -eq 1){
        #  foreach($tmp in $teams.psObject.properties)
         foreach($team in $teams)
            {
                $returnObject = $team
                Write-Output $returnObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    }
}
'@ 
$tmpModel = @'
[{"key":"GroupId","type":0},{"key":"InternalId","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0},{"key":"Visibility","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0},{"key":"AllowGiphy","type":0},{"key":"GiphyContentRating","type":0},{"key":"AllowStickersAndMemes","type":0},{"key":"AllowCustomMemes","type":0},{"key":"AllowGuestCreateUpdateChannels","type":0},{"key":"AllowGuestDeleteChannels","type":0},{"key":"AllowCreateUpdateChannels","type":0},{"key":"AllowCreatePrivateChannels","type":0},{"key":"AllowDeleteChannels","type":0},{"key":"AllowAddRemoveApps","type":0},{"key":"AllowCreateUpdateRemoveTabs","type":0},{"key":"AllowCreateUpdateRemoveConnectors","type":0},{"key":"AllowUserEditMessages","type":0},{"key":"AllowUserDeleteMessages","type":0},{"key":"AllowOwnerDeleteMessages","type":0},{"key":"AllowTeamMentions","type":0},{"key":"AllowChannelMentions","type":0},{"key":"ShowInTeamsSearchAndSuggestions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_14 = [PSCustomObject]@{} 
$dataSourceGuid_14_Name = @'
Edit-Team-Details-Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_14_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_14) 
<# End: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>

<# Begin: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $formInput.selectedGroup.GroupId

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
        $teams = Get-Team -GroupId $groupId
        
        if(@($teams).Count -eq 1){
        #  foreach($tmp in $teams.psObject.properties)
         foreach($team in $teams)
            {
                $returnObject = $team
                Write-Output $returnObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    }
}
'@ 
$tmpModel = @'
[{"key":"GroupId","type":0},{"key":"InternalId","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0},{"key":"Visibility","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0},{"key":"AllowGiphy","type":0},{"key":"GiphyContentRating","type":0},{"key":"AllowStickersAndMemes","type":0},{"key":"AllowCustomMemes","type":0},{"key":"AllowGuestCreateUpdateChannels","type":0},{"key":"AllowGuestDeleteChannels","type":0},{"key":"AllowCreateUpdateChannels","type":0},{"key":"AllowCreatePrivateChannels","type":0},{"key":"AllowDeleteChannels","type":0},{"key":"AllowAddRemoveApps","type":0},{"key":"AllowCreateUpdateRemoveTabs","type":0},{"key":"AllowCreateUpdateRemoveConnectors","type":0},{"key":"AllowUserEditMessages","type":0},{"key":"AllowUserDeleteMessages","type":0},{"key":"AllowOwnerDeleteMessages","type":0},{"key":"AllowTeamMentions","type":0},{"key":"AllowChannelMentions","type":0},{"key":"ShowInTeamsSearchAndSuggestions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_3 = [PSCustomObject]@{} 
$dataSourceGuid_3_Name = @'
Edit-Team-Details-Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_3_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_3) 
<# End: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>

<# Begin: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $formInput.selectedGroup.GroupId

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
        $teams = Get-Team -GroupId $groupId
        
        if(@($teams).Count -eq 1){
        #  foreach($tmp in $teams.psObject.properties)
         foreach($team in $teams)
            {
                $returnObject = $team
                Write-Output $returnObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    }
}
'@ 
$tmpModel = @'
[{"key":"GroupId","type":0},{"key":"InternalId","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0},{"key":"Visibility","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0},{"key":"AllowGiphy","type":0},{"key":"GiphyContentRating","type":0},{"key":"AllowStickersAndMemes","type":0},{"key":"AllowCustomMemes","type":0},{"key":"AllowGuestCreateUpdateChannels","type":0},{"key":"AllowGuestDeleteChannels","type":0},{"key":"AllowCreateUpdateChannels","type":0},{"key":"AllowCreatePrivateChannels","type":0},{"key":"AllowDeleteChannels","type":0},{"key":"AllowAddRemoveApps","type":0},{"key":"AllowCreateUpdateRemoveTabs","type":0},{"key":"AllowCreateUpdateRemoveConnectors","type":0},{"key":"AllowUserEditMessages","type":0},{"key":"AllowUserDeleteMessages","type":0},{"key":"AllowOwnerDeleteMessages","type":0},{"key":"AllowTeamMentions","type":0},{"key":"AllowChannelMentions","type":0},{"key":"ShowInTeamsSearchAndSuggestions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_10 = [PSCustomObject]@{} 
$dataSourceGuid_10_Name = @'
Edit-Team-Details-Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_10_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_10) 
<# End: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>

<# Begin: DataSource "Edit-Team-Details-Teams-get-teams" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
	    $teams = Get-Team
        Write-Information "Result count: $(@($teams).Count)"

        if(@($teams).Count -gt 0){
            foreach($team in $teams)
            {
                $resultObject = @{DisplayName=$team.DisplayName; Description=$team.Description; MailNickName=$team.MailNickName; Visibility=$team.Visibility; Archived=$team.Archived; GroupId=$team.GroupId;}
                Write-Output $resultObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Teams. Error: $($_.Exception.Message)"
	}
}

'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"Visibility","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
Edit-Team-Details-Teams-get-teams
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "Edit-Team-Details-Teams-get-teams" #>

<# Begin: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $formInput.selectedGroup.GroupId

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
        $teams = Get-Team -GroupId $groupId
        
        if(@($teams).Count -eq 1){
        #  foreach($tmp in $teams.psObject.properties)
         foreach($team in $teams)
            {
                $returnObject = $team
                Write-Output $returnObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    }
}
'@ 
$tmpModel = @'
[{"key":"GroupId","type":0},{"key":"InternalId","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0},{"key":"Visibility","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0},{"key":"AllowGiphy","type":0},{"key":"GiphyContentRating","type":0},{"key":"AllowStickersAndMemes","type":0},{"key":"AllowCustomMemes","type":0},{"key":"AllowGuestCreateUpdateChannels","type":0},{"key":"AllowGuestDeleteChannels","type":0},{"key":"AllowCreateUpdateChannels","type":0},{"key":"AllowCreatePrivateChannels","type":0},{"key":"AllowDeleteChannels","type":0},{"key":"AllowAddRemoveApps","type":0},{"key":"AllowCreateUpdateRemoveTabs","type":0},{"key":"AllowCreateUpdateRemoveConnectors","type":0},{"key":"AllowUserEditMessages","type":0},{"key":"AllowUserDeleteMessages","type":0},{"key":"AllowOwnerDeleteMessages","type":0},{"key":"AllowTeamMentions","type":0},{"key":"AllowChannelMentions","type":0},{"key":"ShowInTeamsSearchAndSuggestions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_9 = [PSCustomObject]@{} 
$dataSourceGuid_9_Name = @'
Edit-Team-Details-Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_9_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_9) 
<# End: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>

<# Begin: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $formInput.selectedGroup.GroupId

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
        $teams = Get-Team -GroupId $groupId
        
        if(@($teams).Count -eq 1){
        #  foreach($tmp in $teams.psObject.properties)
         foreach($team in $teams)
            {
                $returnObject = $team
                Write-Output $returnObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    }
}
'@ 
$tmpModel = @'
[{"key":"GroupId","type":0},{"key":"InternalId","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0},{"key":"Visibility","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0},{"key":"AllowGiphy","type":0},{"key":"GiphyContentRating","type":0},{"key":"AllowStickersAndMemes","type":0},{"key":"AllowCustomMemes","type":0},{"key":"AllowGuestCreateUpdateChannels","type":0},{"key":"AllowGuestDeleteChannels","type":0},{"key":"AllowCreateUpdateChannels","type":0},{"key":"AllowCreatePrivateChannels","type":0},{"key":"AllowDeleteChannels","type":0},{"key":"AllowAddRemoveApps","type":0},{"key":"AllowCreateUpdateRemoveTabs","type":0},{"key":"AllowCreateUpdateRemoveConnectors","type":0},{"key":"AllowUserEditMessages","type":0},{"key":"AllowUserDeleteMessages","type":0},{"key":"AllowOwnerDeleteMessages","type":0},{"key":"AllowTeamMentions","type":0},{"key":"AllowChannelMentions","type":0},{"key":"ShowInTeamsSearchAndSuggestions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_8 = [PSCustomObject]@{} 
$dataSourceGuid_8_Name = @'
Edit-Team-Details-Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_8_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_8) 
<# End: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>

<# Begin: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $formInput.selectedGroup.GroupId

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
        $teams = Get-Team -GroupId $groupId
        
        if(@($teams).Count -eq 1){
        #  foreach($tmp in $teams.psObject.properties)
         foreach($team in $teams)
            {
                $returnObject = $team
                Write-Output $returnObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    }
}
'@ 
$tmpModel = @'
[{"key":"GroupId","type":0},{"key":"InternalId","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0},{"key":"Visibility","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0},{"key":"AllowGiphy","type":0},{"key":"GiphyContentRating","type":0},{"key":"AllowStickersAndMemes","type":0},{"key":"AllowCustomMemes","type":0},{"key":"AllowGuestCreateUpdateChannels","type":0},{"key":"AllowGuestDeleteChannels","type":0},{"key":"AllowCreateUpdateChannels","type":0},{"key":"AllowCreatePrivateChannels","type":0},{"key":"AllowDeleteChannels","type":0},{"key":"AllowAddRemoveApps","type":0},{"key":"AllowCreateUpdateRemoveTabs","type":0},{"key":"AllowCreateUpdateRemoveConnectors","type":0},{"key":"AllowUserEditMessages","type":0},{"key":"AllowUserDeleteMessages","type":0},{"key":"AllowOwnerDeleteMessages","type":0},{"key":"AllowTeamMentions","type":0},{"key":"AllowChannelMentions","type":0},{"key":"ShowInTeamsSearchAndSuggestions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_15 = [PSCustomObject]@{} 
$dataSourceGuid_15_Name = @'
Edit-Team-Details-Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_15_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_15) 
<# End: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>

<# Begin: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>
$tmpPsScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId = $formInput.selectedGroup.GroupId

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
        $teams = Get-Team -GroupId $groupId
        
        if(@($teams).Count -eq 1){
        #  foreach($tmp in $teams.psObject.properties)
         foreach($team in $teams)
            {
                $returnObject = $team
                Write-Output $returnObject
            }
        }
	}
	catch
	{
		Write-Error "Error getting Team Details. Error: $($_.Exception.Message)"
    }
}
'@ 
$tmpModel = @'
[{"key":"GroupId","type":0},{"key":"InternalId","type":0},{"key":"DisplayName","type":0},{"key":"Description","type":0},{"key":"Visibility","type":0},{"key":"MailNickName","type":0},{"key":"Archived","type":0},{"key":"AllowGiphy","type":0},{"key":"GiphyContentRating","type":0},{"key":"AllowStickersAndMemes","type":0},{"key":"AllowCustomMemes","type":0},{"key":"AllowGuestCreateUpdateChannels","type":0},{"key":"AllowGuestDeleteChannels","type":0},{"key":"AllowCreateUpdateChannels","type":0},{"key":"AllowCreatePrivateChannels","type":0},{"key":"AllowDeleteChannels","type":0},{"key":"AllowAddRemoveApps","type":0},{"key":"AllowCreateUpdateRemoveTabs","type":0},{"key":"AllowCreateUpdateRemoveConnectors","type":0},{"key":"AllowUserEditMessages","type":0},{"key":"AllowUserDeleteMessages","type":0},{"key":"AllowOwnerDeleteMessages","type":0},{"key":"AllowTeamMentions","type":0},{"key":"AllowChannelMentions","type":0},{"key":"ShowInTeamsSearchAndSuggestions","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$dataSourceGuid_5 = [PSCustomObject]@{} 
$dataSourceGuid_5_Name = @'
Edit-Team-Details-Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_5_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_5) 
<# End: DataSource "Edit-Team-Details-Teams-get-team-parameters" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Teams - Edit Team Details" #>
$tmpSchema = @"
[{"label":"Select Team","fields":[{"key":"teams","templateOptions":{"label":"Select team","required":true,"grid":{"columns":[{"headerName":"Description","field":"Description"},{"headerName":"Visibility","field":"Visibility"},{"headerName":"Mail Nick Name","field":"MailNickName"},{"headerName":"Archived","field":"Archived"},{"headerName":"Group Id","field":"GroupId"},{"headerName":"Display Name","field":"DisplayName"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[]}},"useFilter":true,"useDefault":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"Edit Team Details","fields":[{"key":"AllowAddRemoveApps","templateOptions":{"label":"AllowAddRemoveApps","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowAddRemoveApps","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowChannelMentions","templateOptions":{"label":"AllowChannelMentions","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowChannelMentions","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowCreateUpdateChannels","templateOptions":{"label":"AllowCreateUpdateChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowCreateUpdateChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_3","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowCreateUpdateRemoveConnectors","templateOptions":{"label":"AllowCreateUpdateRemoveConnectors","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowCreateUpdateRemoveConnectors","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_4","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowCreateUpdateRemoveTabs","templateOptions":{"label":"AllowCreateUpdateRemoveTabs","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowCreateUpdateRemoveTabs","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_5","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowCustomMemes","templateOptions":{"label":"AllowCustomMemes","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowCustomMemes","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_6","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowDeleteChannels","templateOptions":{"label":"AllowDeleteChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowDeleteChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_7","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowGiphy","templateOptions":{"label":"AllowGiphy","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowGiphy","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_8","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowGuestCreateUpdateChannels","templateOptions":{"label":"AllowGuestCreateUpdateChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowGuestCreateUpdateChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_9","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowGuestDeleteChannels","templateOptions":{"label":"AllowGuestDeleteChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowGuestDeleteChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_10","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowOwnerDeleteMessages","templateOptions":{"label":"AllowOwnerDeleteMessages","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowOwnerDeleteMessages","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_11","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowStickersAndMemes","templateOptions":{"label":"AllowStickersAndMemes","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowStickersAndMemes","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_12","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowTeamMentions","templateOptions":{"label":"AllowTeamMentions","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowTeamMentions","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_13","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowUserDeleteMessages","templateOptions":{"label":"AllowUserDeleteMessages","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowUserDeleteMessages","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_14","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"AllowUserEditMessages","templateOptions":{"label":"AllowUserEditMessages","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowUserEditMessages","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_15","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"ShowInTeamsSearchAndSuggestions","templateOptions":{"label":"ShowInTeamsSearchAndSuggestions","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"ShowInTeamsSearchAndSuggestions","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_16","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Teams - Edit Team Details
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
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
$delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Compress)
$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Teams - Edit Team Details
'@
$tmpTask = @'
{"name":"Teams - Edit Team Details","script":"#Input: TeamsAdminUser\r\n#Input: TeamsAdminPWD\r\n\r\n# Set TLS to accept TLS, TLS 1.1 and TLS 1.2\r\n[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12\r\n\r\n$VerbosePreference = \"SilentlyContinue\"\r\n$InformationPreference = \"Continue\"\r\n$WarningPreference = \"Continue\"\r\n\r\n# Boolean values come in as string, use this function to convert these to booleans\r\nfunction Convert-StringToBoolean {\r\n    param(\r\n        [parameter(Mandatory = $true)]$String\r\n    )\r\n    try {\r\n        if(-not[String]::IsNullOrEmpty($String)){\r\n            $boolean = [System.Convert]::ToBoolean($String)\r\n            return $boolean\r\n        }else{\r\n            Write-Verbose \"Provided value equals null or empty. Cannot convert to Boolean\"\r\n        }\r\n    } catch {\r\n        throw $_\r\n    }\r\n}\r\n\r\nfunction Remove-EmptyValuesFromHashtable {\r\n    param(\r\n        [parameter(Mandatory = $true)][Hashtable]$Hashtable\r\n    )\r\n\r\n    $newHashtable = @{}\r\n    foreach ($Key in $Hashtable.Keys) {\r\n        if (-not[String]::IsNullOrEmpty($Hashtable.$Key)) {\r\n            $null = $newHashtable.Add($Key, $Hashtable.$Key)\r\n        }\r\n    }\r\n    \r\n    return $newHashtable\r\n}\r\n\r\n# variables configured in form\r\n$groupId                            =   $form.teams.GroupId\r\n$AllowAddRemoveApps                 =   Convert-StringToBoolean $form.AllowAddRemoveApps\r\n$AllowChannelMentions               =   Convert-StringToBoolean $form.AllowChannelMentions\r\n$AllowCreateUpdateChannels          =   Convert-StringToBoolean $form.AllowCreateUpdateChannels\r\n$AllowCreateUpdateRemoveConnectors  =   Convert-StringToBoolean $form.AllowCreateUpdateRemoveConnectors\r\n$AllowCreateUpdateRemoveTabs        =   Convert-StringToBoolean $form.AllowCreateUpdateRemoveTabs \r\n$AllowCustomMemes                   =   Convert-StringToBoolean $form.AllowCustomMemes\r\n$AllowDeleteChannels                =   Convert-StringToBoolean $form.AllowDeleteChannels\r\n$AllowGiphy                         =   Convert-StringToBoolean $form.AllowGiphy\r\n$AllowGuestCreateUpdateChannels     =   Convert-StringToBoolean $form.AllowGuestCreateUpdateChannels\r\n$AllowGuestDeleteChannels           =   Convert-StringToBoolean $form.AllowGuestDeleteChannels\r\n$AllowOwnerDeleteMessages           =   Convert-StringToBoolean $form.AllowOwnerDeleteMessages\r\n$AllowStickersAndMemes              =   Convert-StringToBoolean $form.AllowStickersAndMemes\r\n$AllowTeamMentions                  =   Convert-StringToBoolean $form.AllowTeamMentions\r\n$AllowUserDeleteMessages            =   Convert-StringToBoolean $form.AllowUserDeleteMessages\r\n$AllowUserEditMessages              =   Convert-StringToBoolean $form.AllowUserEditMessages\r\n$ShowInTeamsSearchAndSuggestions    =   Convert-StringToBoolean $form.ShowInTeamsSearchAndSuggestions\r\n\r\n$connected = $false\r\ntry {\r\n\t$module = Import-Module MicrosoftTeams\r\n\t$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force\r\n\t$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd\r\n\t$teamsConnection = Connect-MicrosoftTeams -Credential $cred\r\n    Write-Information \"Connected to Microsoft Teams\"\r\n    $connected = $true\r\n}\r\ncatch\r\n{\t\r\n    Write-Error \"Could not connect to Microsoft Teams. Error: $($_.Exception.Message)\"\r\n}\r\n\r\nif ($connected)\r\n{\r\n\ttry {\r\n        $splatParams = @{\r\n            groupId                             =   $groupId\r\n            AllowAddRemoveApps                  =   $AllowAddRemoveApps\r\n            AllowChannelMentions                =   $AllowChannelMentions\r\n            AllowCreateUpdateChannels           =   $AllowCreateUpdateChannels \r\n            AllowCreateUpdateRemoveConnectors   =   $AllowCreateUpdateRemoveConnectors \r\n            AllowCreateUpdateRemoveTabs         =   $AllowCreateUpdateRemoveTabs \r\n            AllowCustomMemes                    =   $AllowCustomMemes \r\n            AllowDeleteChannels                 =   $AllowDeleteChannels \r\n            AllowGiphy                          =   $AllowGiphy\r\n            AllowGuestCreateUpdateChannels      =   $AllowGuestCreateUpdateChannels\r\n            AllowGuestDeleteChannels            =   $AllowGuestDeleteChannels\r\n            AllowOwnerDeleteMessages            =   $AllowOwnerDeleteMessages\r\n            AllowStickersAndMemes               =   $AllowStickersAndMemes \r\n            AllowTeamMentions                   =   $AllowTeamMentions \r\n            AllowUserDeleteMessages             =   $AllowUserDeleteMessages \r\n            AllowUserEditMessages               =   $AllowUserEditMessages \r\n            ShowInTeamsSearchAndSuggestions     =   $ShowInTeamsSearchAndSuggestions\r\n        }\r\n\r\n        # Remove empty or null values\r\n        $splatParams = Remove-EmptyValuesFromHashtable $splatParams\r\n\r\n\t\t$updateTeam = Set-Team @splatParams\r\n\t\tWrite-Information \"Successfully updated Team [$groupId]\"\r\n\t}\r\n\tcatch\r\n\t{\r\n\t\tWrite-Error \"Could not update Team [$groupId]. Error: $($_.Exception.Message)\"\r\n\t}\r\n}","runInCloud":false}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-pencil-square" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

