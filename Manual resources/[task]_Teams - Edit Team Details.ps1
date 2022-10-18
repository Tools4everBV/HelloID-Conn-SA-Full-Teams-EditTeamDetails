# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$baseGraphUri = "https://graph.microsoft.com/"

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$groupId     =   $form.teams.GroupId
$displayName = $form.teams.DisplayName

if ($form.giphyContentRating -eq "true") { $giphyContentRating = "Strict" } else { $giphyContentRating = "Moderate" }

# Create authorization token and add to headers
try {
    Write-Information "Generating Microsoft Graph API Access Token"

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type    = "client_credentials"
        client_id     = "$AADAppId"
        client_secret = "$AADAppSecret"
        resource      = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization  = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept         = "application/json";
    }
}
catch {
    throw "Could not generate Microsoft Graph API Access Token. Error: $($_.Exception.Message)"    
}


try {
	$updateTeamUri = $baseGraphUri + "v1.0/teams/$groupId"

    $teambody = 
        @"
    {
        "memberSettings": {
            "allowCreatePrivateChannels" : "$($form.AllowCreatePrivateChannels)",
            "allowCreateUpdateChannels": "$($form.AllowCreateUpdateChannels)",
            "allowDeleteChannels": "$($form.AllowDeleteChannels)",
            "allowAddRemoveApps": "$($form.AllowAddRemoveApps)",
            "allowCreateUpdateRemoveTabs": "$($form.AllowCreateUpdateRemoveTabs)",
            "allowCreateUpdateRemoveConnectors": "$($form.AllowCreateUpdateRemoveConnectors)"
        },
        "guestSettings": {
            "allowCreateUpdateChannels": "$($form.AllowGuestCreateUpdateChannels)",
            "allowDeleteChannels": "$($form.AllowGuestDeleteChannels)"
        },
        "messagingSettings": {
            "allowUserEditMessages": "$($form.AllowUserEditMessages)",
            "allowUserDeleteMessages": "$($form.AllowUserDeleteMessages)",
            "allowOwnerDeleteMessages": "$($form.AllowOwnerDeleteMessages)",
            "allowTeamMentions": "$($form.AllowTeamMentions)",
            "allowChannelMentions": "$($form.AllowChannelMentions)"
        },
        "funSettings": {
            "allowGiphy": "$($form.AllowGiphy)",
            "giphyContentRating": "$giphyContentRating",
            "allowStickersAndMemes": "$($form.AllowStickersAndMemes)",
            "allowCustomMemes": "$($form.AllowCustomMemes)"
        }
    }
"@
    
    $updateteam = Invoke-RestMethod -Method PATCH -Uri $updateTeamUri -Body $teambody -Headers $authorization 

    Write-Information "Successfully updated Team [$displayName] with id [$groupId]."
        $Log = @{
            Action            = "UpdateResource" # optional. ENUM (undefined = default) 
            System            = "AzureActiveDirectory" # optional (free format text) 
            Message           = "Successfully updated Team [$displayName] with id [$groupId]." # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $displayName # optional (free format text)
            TargetIdentifier  = $groupId # optional (free format text)
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
}
catch
{	
    Write-Error "Failed to update Team [$displayName]. Error: $($_.Exception.Message)"
    $Log = @{
        Action            = "UpdateResource" # optional. ENUM (undefined = default) 
        System            = "AzureActiveDirectory" # optional (free format text) 
        Message           = "Failed to update team [$displayName] with id [$groupId]." # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $displayName # optional (free format text)
        TargetIdentifier  = $groupId # optional (free format text)
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}

try {
	$updateBetaTeamUri = $baseGraphUri + "beta/teams/$groupId"

    $teambetabody = 
        @"
    {
        "discoverySettings": {
            "showInTeamsSearchAndSuggestions" : "$($form.ShowInTeamsSearchAndSuggestions)"
        }
    }
"@

    $updatebetateam = Invoke-RestMethod -Method PATCH -Uri $updateBetaTeamUri -Body $teambetabody -Headers $authorization 

    Write-Information "Successfully updated betasettings Team [$displayName] with id [$groupId]."
        $Log = @{
            Action            = "UpdateResource" # optional. ENUM (undefined = default) 
            System            = "AzureActiveDirectory" # optional (free format text) 
            Message           = "Successfully updated betasettings Team [$displayName] with id [$groupId]." # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $displayName # optional (free format text)
            TargetIdentifier  = $groupId # optional (free format text)
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
}
catch
{	
     Write-Error "Failed to update betasettings Team [$displayName]. Error: $($_.Exception.Message)"
    $Log = @{
        Action            = "UpdateResource" # optional. ENUM (undefined = default) 
        System            = "AzureActiveDirectory" # optional (free format text) 
        Message           = "Failed to update betasettings team [$displayName] with id [$groupId]." # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $displayName # optional (free format text)
        TargetIdentifier  = $groupId # optional (free format text)
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
}
