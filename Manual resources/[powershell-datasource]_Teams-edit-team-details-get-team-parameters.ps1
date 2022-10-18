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
