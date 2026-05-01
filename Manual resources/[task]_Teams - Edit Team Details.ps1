#######################################################################
# Template: HelloID SA Delegated form task
# Name: Teams - Edit Team Details
# Date: 03-04-2026
#######################################################################

# For basic information about delegated form tasks see:
# https://docs.helloid.com/en/service-automation/delegated-forms/delegated-form-tasks.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable libary):
# Outcommented as these are set from Global Variables
# $EntraIdTenantId = ""
# $EntraIdAppId = ""
# $EntraIdCertificateBase64String = ""
# $EntraIdCertificatePassword = ""

# variables configured in form
$groupId = $form.teams.GroupId
$currentDisplayName = $form.teams.DisplayName
$displayName = $form.teamDisplayName
$description = $form.teamDescription
$visibility = $form.teamVisibility.value
$ownersToAdd = @($form.teamOwners.leftToRight)
$ownersToRemove = @($form.teamOwners.rightToLeft)

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
    if ($form.giphyContentRating -eq 'true') {
        $giphyContentRating = "Strict"
    }
    else {
        $giphyContentRating = "Moderate"
    }

    $actionMessage = "authenticating to Microsoft Graph"
    Write-Verbose 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $authorization = @{
        Authorization  = "Bearer $entraToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $actionMessage = "updating team metadata for Team [$currentDisplayName] with ID [$groupId]"
    $groupBody = @{
        displayName = $displayName
        description = $description
        visibility  = $visibility
    }
    Write-Information "Updating team metadata for Team [$currentDisplayName] with ID [$groupId]. New display name: [$displayName], description: [$description], visibility: [$visibility]."

    $updateGroupSplatParams = @{
        Uri         = "https://graph.microsoft.com/v1.0/groups/$groupId"
        Body        = ($groupBody | ConvertTo-Json -Depth 10)
        Headers     = $authorization
        Method      = 'PATCH'
        ContentType = 'application/json'
        Verbose     = $false
        ErrorAction = 'Stop'
    }
    $null = Invoke-RestMethod @updateGroupSplatParams

    $actionMessage = "updating team settings for Team [$displayName] with ID [$groupId]"
    $teamBody = @{
        memberSettings    = @{
            allowCreatePrivateChannels        = [System.Convert]::ToBoolean($form.AllowCreatePrivateChannels)
            allowCreateUpdateChannels         = [System.Convert]::ToBoolean($form.AllowCreateUpdateChannels)
            allowDeleteChannels               = [System.Convert]::ToBoolean($form.AllowDeleteChannels)
            allowAddRemoveApps                = [System.Convert]::ToBoolean($form.AllowAddRemoveApps)
            allowCreateUpdateRemoveTabs       = [System.Convert]::ToBoolean($form.AllowCreateUpdateRemoveTabs)
            allowCreateUpdateRemoveConnectors = [System.Convert]::ToBoolean($form.AllowCreateUpdateRemoveConnectors)
        }
        guestSettings     = @{
            allowCreateUpdateChannels = [System.Convert]::ToBoolean($form.AllowGuestCreateUpdateChannels)
            allowDeleteChannels       = [System.Convert]::ToBoolean($form.AllowGuestDeleteChannels)
        }
        messagingSettings = @{
            allowUserEditMessages    = [System.Convert]::ToBoolean($form.AllowUserEditMessages)
            allowUserDeleteMessages  = [System.Convert]::ToBoolean($form.AllowUserDeleteMessages)
            allowOwnerDeleteMessages = [System.Convert]::ToBoolean($form.AllowOwnerDeleteMessages)
            allowTeamMentions        = [System.Convert]::ToBoolean($form.AllowTeamMentions)
            allowChannelMentions     = [System.Convert]::ToBoolean($form.AllowChannelMentions)
        }
        funSettings       = @{
            allowGiphy            = [System.Convert]::ToBoolean($form.AllowGiphy)
            giphyContentRating    = $giphyContentRating
            allowStickersAndMemes = [System.Convert]::ToBoolean($form.AllowStickersAndMemes)
            allowCustomMemes      = [System.Convert]::ToBoolean($form.AllowCustomMemes)
        }
    }

    $updateTeamSplatParams = @{
        Uri         = "https://graph.microsoft.com/v1.0/teams/$groupId"
        Body        = ($teamBody | ConvertTo-Json -Depth 10)
        Headers     = $authorization
        Method      = 'PATCH'
        ContentType = 'application/json'
        Verbose     = $false
        ErrorAction = 'Stop'
    }
    $null = Invoke-RestMethod @updateTeamSplatParams

    if ($ownersToAdd.Count -gt 0) {
        $ownersToAddDisplayNames = $ownersToAdd | Select-Object -ExpandProperty userPrincipalName
        $ownerIdsToAdd = $ownersToAdd | Select-Object -ExpandProperty id

        $actionMessage = "adding team owners for Team [$displayName] with ID [$groupId]"
        Write-Information "Adding team owners for Team [$displayName] with ID [$groupId]. Owners to add (UserPrincipalName): $ownersToAddDisplayNames."

        foreach ($ownerId in $ownerIdsToAdd) {
            Write-Information "Adding user with ID [$ownerId] as owner to Team [$displayName] with ID [$groupId]."
            $ownerRefBody = @{
                '@odata.id' = "https://graph.microsoft.com/v1.0/users/$ownerId"
            }
            $addOwnerSplatParams = @{
                Uri         = "https://graph.microsoft.com/v1.0/groups/$groupId/owners/`$ref"
                Body        = ($ownerRefBody | ConvertTo-Json -Depth 5)
                Headers     = $authorization
                Method      = 'POST'
                ContentType = 'application/json'
                Verbose     = $false
                ErrorAction = 'Stop'
            }
            $null = Invoke-RestMethod @addOwnerSplatParams
        }
    }
    if ($ownersToRemove.Count -gt 0) {
        $ownersToRemoveDisplayNames = $ownersToRemove | Select-Object -ExpandProperty userPrincipalName
        $ownerIdsToRemove = $ownersToRemove | Select-Object -ExpandProperty id

        $actionMessage = "removing team owners for Team [$displayName] with ID [$groupId]"
        Write-Information "Removing team owners for Team [$displayName] with ID [$groupId]. Owners to remove (UserPrincipalName): $ownersToRemoveDisplayNames."

        foreach ($ownerId in $ownerIdsToRemove) {
            Write-Information "Removing user with ID [$ownerId] as owner from Team [$displayName] with ID [$groupId]."
            $removeOwnerSplatParams = @{
                Uri         = "https://graph.microsoft.com/v1.0/groups/$groupId/owners/$ownerId/`$ref"
                Headers     = $authorization
                Method      = 'DELETE'
                ContentType = 'application/json'
                Verbose     = $false
                ErrorAction = 'Stop'
            }
            $null = Invoke-RestMethod @removeOwnerSplatParams
        }
    }

    Write-Information "Successfully updated Team [$displayName] with ID [$groupId]."
    $Log = @{
        Action            = "UpdateResource"
        System            = "MicrosoftTeams"
        Message           = "Successfully updated Team [$displayName] with ID [$groupId]."
        IsError           = $false
        TargetDisplayName = $displayName
        TargetIdentifier  = $groupId
    }
    Write-Information -Tags "Audit" -MessageData $log
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

    $Log = @{
        Action            = "UpdateResource"
        System            = "MicrosoftTeams"
        Message           = $auditMessage
        IsError           = $true
        TargetDisplayName = $displayName
        TargetIdentifier  = $groupId
    }
    Write-Information -Tags "Audit" -MessageData $log
    Write-Warning $warningMessage
    Write-Error $auditMessage
}

