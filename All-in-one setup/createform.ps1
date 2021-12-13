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

#Global variable #1 >> TeamsAdminPWD
$tmpName = @'
TeamsAdminPWD
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

#Global variable #2 >> TeamsAdminUser
$tmpName = @'
TeamsAdminUser
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
<# Begin: DataSource "Teams-get-teams" #>
$tmpScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText ?Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	try {
	    $teams = Get-Team

        if(@($teams).Count -gt 0){
         foreach($team in $teams)
            {
                $addRow = @{DisplayName=$team.DisplayName; Description=$team.Description; MailNickName=$team.MailNickName; Visibility=$team.Visibility; Archived=$team.Archived; GroupId=$team.GroupId;}
                Hid-Write-Status -Message "$addRow" -Event Information
                Hid-Add-TaskResult -ResultValue $addRow
            }
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Teams. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Teams" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
Teams-Get-teams
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_0_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"Filter for DisplayName","translateDescription":false,"inputFieldType":1,"key":"filterDisplayName","type":0,"options":0}]
'@ 
$tmpModel = @'
[{"key":"Archived","type":0},{"key":"Description","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0},{"key":"MailNickName","type":0},{"key":"Visibility","type":0}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
Teams-get-teams
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "Teams-get-teams" #>

<# Begin: DataSource "Teams-get-team-parameters" #>
$tmpScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD
$groupId = $formInput.selectedGroup.GroupId
#$groupId = '0293ec24-013d-4a3a-ba2b-7836ef8f15dd'

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText ?Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	try {
	    $teams = Get-Team -GroupId $groupId

        if(@($teams).Count -eq 1){
         $returnObject = [ordered]@{}
         foreach($tmp in $teams.psObject.properties)
            {
                $returnObject.add($tmp.Name,$tmp.value)
            }
         Hid-Add-TaskResult -ResultValue $returnObject
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Team Parameters. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Team Parameters" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_16_Name = @'
teams-get-team-parameters
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_16_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"Archived","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0},{"key":"MailNickName","type":0},{"key":"Visibility","type":0}]
'@ 
$dataSourceGuid_16 = [PSCustomObject]@{} 
$dataSourceGuid_16_Name = @'
Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_16_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_16) 
<# End: DataSource "Teams-get-team-parameters" #>

<# Begin: DataSource "Teams-get-team-parameters" #>
$tmpScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD
$groupId = $formInput.selectedGroup.GroupId
#$groupId = '0293ec24-013d-4a3a-ba2b-7836ef8f15dd'

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText ?Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	try {
	    $teams = Get-Team -GroupId $groupId

        if(@($teams).Count -eq 1){
         $returnObject = [ordered]@{}
         foreach($tmp in $teams.psObject.properties)
            {
                $returnObject.add($tmp.Name,$tmp.value)
            }
         Hid-Add-TaskResult -ResultValue $returnObject
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Team Parameters. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Team Parameters" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_15_Name = @'
teams-get-team-parameters
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_15_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"Archived","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0},{"key":"MailNickName","type":0},{"key":"Visibility","type":0}]
'@ 
$dataSourceGuid_15 = [PSCustomObject]@{} 
$dataSourceGuid_15_Name = @'
Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_15_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_15) 
<# End: DataSource "Teams-get-team-parameters" #>

<# Begin: DataSource "Teams-get-team-parameters" #>
$tmpScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD
$groupId = $formInput.selectedGroup.GroupId
#$groupId = '0293ec24-013d-4a3a-ba2b-7836ef8f15dd'

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText ?Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	try {
	    $teams = Get-Team -GroupId $groupId

        if(@($teams).Count -eq 1){
         $returnObject = [ordered]@{}
         foreach($tmp in $teams.psObject.properties)
            {
                $returnObject.add($tmp.Name,$tmp.value)
            }
         Hid-Add-TaskResult -ResultValue $returnObject
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Team Parameters. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Team Parameters" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
teams-get-team-parameters
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_1_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"Archived","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0},{"key":"MailNickName","type":0},{"key":"Visibility","type":0}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "Teams-get-team-parameters" #>

<# Begin: DataSource "Teams-get-team-parameters" #>
$tmpScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD
$groupId = $formInput.selectedGroup.GroupId
#$groupId = '0293ec24-013d-4a3a-ba2b-7836ef8f15dd'

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText ?Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	try {
	    $teams = Get-Team -GroupId $groupId

        if(@($teams).Count -eq 1){
         $returnObject = [ordered]@{}
         foreach($tmp in $teams.psObject.properties)
            {
                $returnObject.add($tmp.Name,$tmp.value)
            }
         Hid-Add-TaskResult -ResultValue $returnObject
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Team Parameters. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Team Parameters" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_3_Name = @'
teams-get-team-parameters
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_3_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"Archived","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0},{"key":"MailNickName","type":0},{"key":"Visibility","type":0}]
'@ 
$dataSourceGuid_3 = [PSCustomObject]@{} 
$dataSourceGuid_3_Name = @'
Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_3_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_3) 
<# End: DataSource "Teams-get-team-parameters" #>

<# Begin: DataSource "Teams-get-team-parameters" #>
$tmpScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD
$groupId = $formInput.selectedGroup.GroupId
#$groupId = '0293ec24-013d-4a3a-ba2b-7836ef8f15dd'

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText ?Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	try {
	    $teams = Get-Team -GroupId $groupId

        if(@($teams).Count -eq 1){
         $returnObject = [ordered]@{}
         foreach($tmp in $teams.psObject.properties)
            {
                $returnObject.add($tmp.Name,$tmp.value)
            }
         Hid-Add-TaskResult -ResultValue $returnObject
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Team Parameters. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Team Parameters" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_5_Name = @'
teams-get-team-parameters
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_5_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"Archived","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0},{"key":"MailNickName","type":0},{"key":"Visibility","type":0}]
'@ 
$dataSourceGuid_5 = [PSCustomObject]@{} 
$dataSourceGuid_5_Name = @'
Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_5_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_5) 
<# End: DataSource "Teams-get-team-parameters" #>

<# Begin: DataSource "Teams-get-team-parameters" #>
$tmpScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD
$groupId = $formInput.selectedGroup.GroupId
#$groupId = '0293ec24-013d-4a3a-ba2b-7836ef8f15dd'

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText ?Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	try {
	    $teams = Get-Team -GroupId $groupId

        if(@($teams).Count -eq 1){
         $returnObject = [ordered]@{}
         foreach($tmp in $teams.psObject.properties)
            {
                $returnObject.add($tmp.Name,$tmp.value)
            }
         Hid-Add-TaskResult -ResultValue $returnObject
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Team Parameters. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Team Parameters" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_11_Name = @'
teams-get-team-parameters
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_11_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"Archived","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0},{"key":"MailNickName","type":0},{"key":"Visibility","type":0}]
'@ 
$dataSourceGuid_11 = [PSCustomObject]@{} 
$dataSourceGuid_11_Name = @'
Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_11_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_11) 
<# End: DataSource "Teams-get-team-parameters" #>

<# Begin: DataSource "Teams-get-team-parameters" #>
$tmpScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD
$groupId = $formInput.selectedGroup.GroupId
#$groupId = '0293ec24-013d-4a3a-ba2b-7836ef8f15dd'

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText ?Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	try {
	    $teams = Get-Team -GroupId $groupId

        if(@($teams).Count -eq 1){
         $returnObject = [ordered]@{}
         foreach($tmp in $teams.psObject.properties)
            {
                $returnObject.add($tmp.Name,$tmp.value)
            }
         Hid-Add-TaskResult -ResultValue $returnObject
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Team Parameters. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Team Parameters" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_13_Name = @'
teams-get-team-parameters
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_13_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"Archived","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0},{"key":"MailNickName","type":0},{"key":"Visibility","type":0}]
'@ 
$dataSourceGuid_13 = [PSCustomObject]@{} 
$dataSourceGuid_13_Name = @'
Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_13_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_13) 
<# End: DataSource "Teams-get-team-parameters" #>

<# Begin: DataSource "Teams-get-team-parameters" #>
$tmpScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD
$groupId = $formInput.selectedGroup.GroupId
#$groupId = '0293ec24-013d-4a3a-ba2b-7836ef8f15dd'

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText ?Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	try {
	    $teams = Get-Team -GroupId $groupId

        if(@($teams).Count -eq 1){
         $returnObject = [ordered]@{}
         foreach($tmp in $teams.psObject.properties)
            {
                $returnObject.add($tmp.Name,$tmp.value)
            }
         Hid-Add-TaskResult -ResultValue $returnObject
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Team Parameters. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Team Parameters" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_12_Name = @'
teams-get-team-parameters
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_12_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"Archived","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0},{"key":"MailNickName","type":0},{"key":"Visibility","type":0}]
'@ 
$dataSourceGuid_12 = [PSCustomObject]@{} 
$dataSourceGuid_12_Name = @'
Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_12_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_12) 
<# End: DataSource "Teams-get-team-parameters" #>

<# Begin: DataSource "Teams-get-team-parameters" #>
$tmpScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD
$groupId = $formInput.selectedGroup.GroupId
#$groupId = '0293ec24-013d-4a3a-ba2b-7836ef8f15dd'

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText ?Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	try {
	    $teams = Get-Team -GroupId $groupId

        if(@($teams).Count -eq 1){
         $returnObject = [ordered]@{}
         foreach($tmp in $teams.psObject.properties)
            {
                $returnObject.add($tmp.Name,$tmp.value)
            }
         Hid-Add-TaskResult -ResultValue $returnObject
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Team Parameters. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Team Parameters" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_10_Name = @'
teams-get-team-parameters
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_10_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"Archived","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0},{"key":"MailNickName","type":0},{"key":"Visibility","type":0}]
'@ 
$dataSourceGuid_10 = [PSCustomObject]@{} 
$dataSourceGuid_10_Name = @'
Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_10_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_10) 
<# End: DataSource "Teams-get-team-parameters" #>

<# Begin: DataSource "Teams-get-team-parameters" #>
$tmpScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD
$groupId = $formInput.selectedGroup.GroupId
#$groupId = '0293ec24-013d-4a3a-ba2b-7836ef8f15dd'

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText ?Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	try {
	    $teams = Get-Team -GroupId $groupId

        if(@($teams).Count -eq 1){
         $returnObject = [ordered]@{}
         foreach($tmp in $teams.psObject.properties)
            {
                $returnObject.add($tmp.Name,$tmp.value)
            }
         Hid-Add-TaskResult -ResultValue $returnObject
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Team Parameters. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Team Parameters" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
teams-get-team-parameters
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_2_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"Archived","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0},{"key":"MailNickName","type":0},{"key":"Visibility","type":0}]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "Teams-get-team-parameters" #>

<# Begin: DataSource "Teams-get-team-parameters" #>
$tmpScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD
$groupId = $formInput.selectedGroup.GroupId
#$groupId = '0293ec24-013d-4a3a-ba2b-7836ef8f15dd'

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText ?Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	try {
	    $teams = Get-Team -GroupId $groupId

        if(@($teams).Count -eq 1){
         $returnObject = [ordered]@{}
         foreach($tmp in $teams.psObject.properties)
            {
                $returnObject.add($tmp.Name,$tmp.value)
            }
         Hid-Add-TaskResult -ResultValue $returnObject
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Team Parameters. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Team Parameters" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_4_Name = @'
teams-get-team-parameters
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_4_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"Archived","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0},{"key":"MailNickName","type":0},{"key":"Visibility","type":0}]
'@ 
$dataSourceGuid_4 = [PSCustomObject]@{} 
$dataSourceGuid_4_Name = @'
Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_4_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_4) 
<# End: DataSource "Teams-get-team-parameters" #>

<# Begin: DataSource "Teams-get-team-parameters" #>
$tmpScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD
$groupId = $formInput.selectedGroup.GroupId
#$groupId = '0293ec24-013d-4a3a-ba2b-7836ef8f15dd'

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText ?Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	try {
	    $teams = Get-Team -GroupId $groupId

        if(@($teams).Count -eq 1){
         $returnObject = [ordered]@{}
         foreach($tmp in $teams.psObject.properties)
            {
                $returnObject.add($tmp.Name,$tmp.value)
            }
         Hid-Add-TaskResult -ResultValue $returnObject
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Team Parameters. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Team Parameters" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_6_Name = @'
teams-get-team-parameters
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_6_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"Archived","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0},{"key":"MailNickName","type":0},{"key":"Visibility","type":0}]
'@ 
$dataSourceGuid_6 = [PSCustomObject]@{} 
$dataSourceGuid_6_Name = @'
Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_6_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_6) 
<# End: DataSource "Teams-get-team-parameters" #>

<# Begin: DataSource "Teams-get-team-parameters" #>
$tmpScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD
$groupId = $formInput.selectedGroup.GroupId
#$groupId = '0293ec24-013d-4a3a-ba2b-7836ef8f15dd'

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText ?Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	try {
	    $teams = Get-Team -GroupId $groupId

        if(@($teams).Count -eq 1){
         $returnObject = [ordered]@{}
         foreach($tmp in $teams.psObject.properties)
            {
                $returnObject.add($tmp.Name,$tmp.value)
            }
         Hid-Add-TaskResult -ResultValue $returnObject
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Team Parameters. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Team Parameters" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_7_Name = @'
teams-get-team-parameters
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_7_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"Archived","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0},{"key":"MailNickName","type":0},{"key":"Visibility","type":0}]
'@ 
$dataSourceGuid_7 = [PSCustomObject]@{} 
$dataSourceGuid_7_Name = @'
Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_7_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_7) 
<# End: DataSource "Teams-get-team-parameters" #>

<# Begin: DataSource "Teams-get-team-parameters" #>
$tmpScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD
$groupId = $formInput.selectedGroup.GroupId
#$groupId = '0293ec24-013d-4a3a-ba2b-7836ef8f15dd'

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText ?Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	try {
	    $teams = Get-Team -GroupId $groupId

        if(@($teams).Count -eq 1){
         $returnObject = [ordered]@{}
         foreach($tmp in $teams.psObject.properties)
            {
                $returnObject.add($tmp.Name,$tmp.value)
            }
         Hid-Add-TaskResult -ResultValue $returnObject
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Team Parameters. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Team Parameters" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_9_Name = @'
teams-get-team-parameters
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_9_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"Archived","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0},{"key":"MailNickName","type":0},{"key":"Visibility","type":0}]
'@ 
$dataSourceGuid_9 = [PSCustomObject]@{} 
$dataSourceGuid_9_Name = @'
Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_9_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_9) 
<# End: DataSource "Teams-get-team-parameters" #>

<# Begin: DataSource "Teams-get-team-parameters" #>
$tmpScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD
$groupId = $formInput.selectedGroup.GroupId
#$groupId = '0293ec24-013d-4a3a-ba2b-7836ef8f15dd'

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText ?Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	try {
	    $teams = Get-Team -GroupId $groupId

        if(@($teams).Count -eq 1){
         $returnObject = [ordered]@{}
         foreach($tmp in $teams.psObject.properties)
            {
                $returnObject.add($tmp.Name,$tmp.value)
            }
         Hid-Add-TaskResult -ResultValue $returnObject
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Team Parameters. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Team Parameters" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_14_Name = @'
teams-get-team-parameters
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_14_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"Archived","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0},{"key":"MailNickName","type":0},{"key":"Visibility","type":0}]
'@ 
$dataSourceGuid_14 = [PSCustomObject]@{} 
$dataSourceGuid_14_Name = @'
Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_14_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_14) 
<# End: DataSource "Teams-get-team-parameters" #>

<# Begin: DataSource "Teams-get-team-parameters" #>
$tmpScript = @'
#Input: TeamsAdminUser
#Input: TeamsAdminPWD
$groupId = $formInput.selectedGroup.GroupId
#$groupId = '0293ec24-013d-4a3a-ba2b-7836ef8f15dd'

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText ?Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}

if ($connected)
{
	try {
	    $teams = Get-Team -GroupId $groupId

        if(@($teams).Count -eq 1){
         $returnObject = [ordered]@{}
         foreach($tmp in $teams.psObject.properties)
            {
                $returnObject.add($tmp.Name,$tmp.value)
            }
         Hid-Add-TaskResult -ResultValue $returnObject
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Team Parameters. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Team Parameters" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

'@; 

$tmpVariables = @'

'@ 

$taskGuid = [PSCustomObject]@{} 
$dataSourceGuid_8_Name = @'
teams-get-team-parameters
'@ 
Invoke-HelloIDAutomationTask -TaskName $dataSourceGuid_8_Name -UseTemplate "False" -AutomationContainer "1" -Variables $tmpVariables -PowershellScript $tmpScript -returnObject ([Ref]$taskGuid) 

$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":0}]
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"Archived","type":0},{"key":"GroupId","type":0},{"key":"DisplayName","type":0},{"key":"MailNickName","type":0},{"key":"Visibility","type":0}]
'@ 
$dataSourceGuid_8 = [PSCustomObject]@{} 
$dataSourceGuid_8_Name = @'
Teams-get-team-parameters
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_8_Name -DatasourceType "3" -DatasourceInput $tmpInput -DatasourceModel $tmpModel -AutomationTaskGuid $taskGuid -returnObject ([Ref]$dataSourceGuid_8) 
<# End: DataSource "Teams-get-team-parameters" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Teams - Edit Team Details" #>
$tmpSchema = @"
[{"label":"Select Team","fields":[{"key":"filterDisplayName","templateOptions":{"label":"Search for DisplayName","required":false},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"teams","templateOptions":{"label":"Select Team","required":true,"grid":{"columns":[{"headerName":"Display Name","field":"DisplayName"},{"headerName":"Description","field":"Description"},{"headerName":"Mail Nick Name","field":"MailNickName"},{"headerName":"Visibility","field":"Visibility"},{"headerName":"Archived","field":"Archived"},{"headerName":"Group Id","field":"GroupId"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"filterDisplayName","otherFieldValue":{"otherFieldKey":"filterDisplayName"}}]}},"useFilter":false,"useDefault":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true}]},{"label":"Edit Team Details","fields":[{"key":"AllowAddRemoveApps","templateOptions":{"label":"AllowAddRemoveApps","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowAddRemoveApps","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"AllowChannelMentions","templateOptions":{"label":"AllowChannelMentions","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowChannelMentions","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"AllowCreateUpdateChannels","templateOptions":{"label":"AllowCreateUpdateChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowCreateUpdateChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_3","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"AllowCreateUpdateRemoveConnectors","templateOptions":{"label":"AllowCreateUpdateRemoveConnectors","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowCreateUpdateRemoveConnectors","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_4","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"AllowCreateUpdateRemoveTabs","templateOptions":{"label":"AllowCreateUpdateRemoveTabs","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowCreateUpdateRemoveTabs","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_5","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"AllowCustomMemes","templateOptions":{"label":"AllowCustomMemes","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowCustomMemes","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_6","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"AllowDeleteChannels","templateOptions":{"label":"AllowDeleteChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowDeleteChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_7","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"AllowGiphy","templateOptions":{"label":"AllowGiphy","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowGiphy","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_8","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"AllowGuestCreateUpdateChannels","templateOptions":{"label":"AllowGuestCreateUpdateChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowGuestCreateUpdateChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_9","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"AllowGuestDeleteChannels","templateOptions":{"label":"AllowGuestDeleteChannels","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowGuestDeleteChannels","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_10","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"AllowOwnerDeleteMessages","templateOptions":{"label":"AllowOwnerDeleteMessages","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowOwnerDeleteMessages","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_11","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"AllowStickersAndMemes","templateOptions":{"label":"AllowStickersAndMemes","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowStickersAndMemes","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_12","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"AllowTeamMentions","templateOptions":{"label":"AllowTeamMentions","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowTeamMentions","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_13","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"AllowUserDeleteMessages","templateOptions":{"label":"AllowUserDeleteMessages","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowUserDeleteMessages","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_14","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"AllowUserEditMessages","templateOptions":{"label":"AllowUserEditMessages","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"AllowUserEditMessages","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_15","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true},{"key":"ShowInTeamsSearchAndSuggestions","templateOptions":{"label":"ShowInTeamsSearchAndSuggestions","useSwitch":true,"checkboxLabel":"Allow","useDataSource":true,"displayField":"ShowInTeamsSearchAndSuggestions","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_16","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"teams"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true}]}]
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
Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-pencil-square" -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

<# Begin: Delegated Form Task #>
if($delegatedFormRef.created -eq $true) { 
	$tmpScript = @'
$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}
if ($connected)
{
	try {
		Set-Team -groupId $groupId -AllowAddRemoveApps $AllowAddRemoveApps -AllowChannelMentions $AllowChannelMentions -AllowCreateUpdateChannels $AllowCreateUpdateChannels -AllowCreateUpdateRemoveConnectors $AllowCreateUpdateRemoveConnectors -AllowCreateUpdateRemoveTabs $AllowCreateUpdateRemoveTabs -AllowCustomMemes $AllowCustomMemes -AllowDeleteChannels $AllowDeleteChannels -AllowGiphy $AllowGiphy -AllowGuestCreateUpdateChannels $AllowGuestCreateUpdateChannels -AllowGuestDeleteChannels $AllowGuestDeleteChannels -AllowOwnerDeleteMessages $AllowOwnerDeleteMessages -AllowStickersAndMemes $AllowStickersAndMemes -AllowTeamMentions $AllowTeamMentions -AllowUserDeleteMessages $AllowUserDeleteMessages -AllowUserEditMessages $AllowUserEditMessages -ShowInTeamsSearchAndSuggestions $ShowInTeamsSearchAndSuggestions
		HID-Write-Status -Message "Updated Team [$groupId]" -Event Success
		HID-Write-Summary -Message "Successfully update Team [$groupId]" -Event Success
	}
	catch
	{
		HID-Write-Status -Message "Could not update Team [$groupId]. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Failed to update Team [$groupId]" -Event Failed
	}
}
'@; 

	$tmpVariables = @'
[{"name":"AllowAddRemoveApps","value":"{{form.AllowAddRemoveApps}}","secret":false,"typeConstraint":"string"},{"name":"AllowChannelMentions","value":"{{form.AllowChannelMentions}}","secret":false,"typeConstraint":"string"},{"name":"AllowCreateUpdateChannels","value":"{{form.AllowCreateUpdateChannels}}","secret":false,"typeConstraint":"string"},{"name":"AllowCreateUpdateRemoveConnectors","value":"{{form.AllowCreateUpdateRemoveConnectors}}","secret":false,"typeConstraint":"string"},{"name":"AllowCreateUpdateRemoveTabs","value":"{{form.AllowCreateUpdateRemoveTabs}}","secret":false,"typeConstraint":"string"},{"name":"AllowCustomMemes","value":"{{form.AllowCustomMemes}}","secret":false,"typeConstraint":"string"},{"name":"AllowDeleteChannels","value":"{{form.AllowDeleteChannels}}","secret":false,"typeConstraint":"string"},{"name":"AllowGiphy","value":"{{form.AllowGiphy}}","secret":false,"typeConstraint":"string"},{"name":"AllowGuestCreateUpdateChannels","value":"{{form.AllowGuestCreateUpdateChannels}}","secret":false,"typeConstraint":"string"},{"name":"AllowGuestDeleteChannels","value":"{{form.AllowGuestDeleteChannels}}","secret":false,"typeConstraint":"string"},{"name":"AllowOwnerDeleteMessages","value":"{{form.AllowOwnerDeleteMessages}}","secret":false,"typeConstraint":"string"},{"name":"AllowStickersAndMemes","value":"{{form.AllowStickersAndMemes}}","secret":false,"typeConstraint":"string"},{"name":"AllowTeamMentions","value":"{{form.AllowTeamMentions}}","secret":false,"typeConstraint":"string"},{"name":"AllowUserDeleteMessages","value":"{{form.AllowUserDeleteMessages}}","secret":false,"typeConstraint":"string"},{"name":"AllowUserEditMessages","value":"{{form.AllowUserEditMessages}}","secret":false,"typeConstraint":"string"},{"name":"groupId","value":"{{form.teams.GroupId}}","secret":false,"typeConstraint":"string"},{"name":"ShowInTeamsSearchAndSuggestions","value":"{{form.ShowInTeamsSearchAndSuggestions}}","secret":false,"typeConstraint":"string"}]
'@ 

	$delegatedFormTaskGuid = [PSCustomObject]@{} 
$delegatedFormTaskName = @'
Teams-edit-team-details
'@
	Invoke-HelloIDAutomationTask -TaskName $delegatedFormTaskName -UseTemplate "False" -AutomationContainer "8" -Variables $tmpVariables -PowershellScript $tmpScript -ObjectGuid $delegatedFormRef.guid -ForceCreateTask $true -returnObject ([Ref]$delegatedFormTaskGuid) 
} else {
	Write-Warning "Delegated form '$delegatedFormName' already exists. Nothing to do with the Delegated Form task..." 
}
<# End: Delegated Form Task #>
