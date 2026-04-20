# HelloID-Conn-SA-Full-Teams-EditTeamDetails

| :information_source: Information                                                                                                                                                                                                                                                                                                                                                          |
|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible for acquiring the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |

## Description
_HelloID-Conn-SA-Full-Teams-EditTeamDetails_ is a template designed for use with HelloID Service Automation (SA) Delegated Forms. It can be imported into HelloID and customized according to your requirements.

By using this delegated form, you can update Team settings in Microsoft Teams through Microsoft Graph. The delegated form supports the following flow:
1. Search for and select an existing Microsoft Team
2. Retrieve Team metadata and Team settings into the form
3. Optionally update Team display name, description, and privacy
4. Add and/or remove Team owners by moving users between source and destination lists
5. Validate Team naming uniqueness before submit
6. Update Team metadata and Team settings

## Getting started
### Requirements

- **Microsoft Entra application registration (certificate-based)**:
  The connector authenticates to Microsoft Graph using a certificate (client credentials flow).
- **Microsoft Graph application permissions**:
  Configure and grant admin consent for the following minimal application permissions:
  - `GroupMember.Read.All`
  - `Group.ReadWrite.All`
  - `TeamSettings.ReadWrite.Group`
  - `User.Read.All`

### Connection settings

The following user-defined variables are used by the connector.

| Setting                        | Description                                                                | Mandatory |
|--------------------------------|----------------------------------------------------------------------------|-----------|
| EntraIdTenantId                | Microsoft Entra tenant ID                                                  | Yes       |
| EntraIdAppId                   | Application (client) ID of the app registration                            | Yes       |
| EntraIdCertificateBase64String | Base64 encoded certificate (including private key) used for authentication | Yes       |
| EntraIdCertificatePassword     | Password for the certificate                                               | Yes       |
| TeamsMailsuffix                | Mail suffix used when building mail address from display name              | Yes       |

## Remarks

### Microsoft Graph Query Behavior
- `ConsistencyLevel: eventual` is added on Graph requests where advanced query capabilities are used (for example filtering and searching result sets).

### Team settings behavior
- Team core settings are updated through `v1.0/teams/{teamId}`.

### Team metadata and owner behavior
- Team metadata is updated through `v1.0/groups/{groupId}`.
- Team owners are synchronized through `v1.0/groups/{groupId}/owners/$ref` for add and remove operations.
- Privacy options are loaded dynamically and include `Public` and `Private`. `HiddenMembership` is only shown when the selected Team already uses this visibility.

### Validation behavior
- The form validates whether display name, mail, and mail nickname are unique before submit.
- Validation excludes the currently selected Team from uniqueness checks.

## Development resources

### API endpoints

The following endpoints are used by the connector.

| Endpoint                                                    | Description                                                             |
|-------------------------------------------------------------|-------------------------------------------------------------------------|
| `https://login.microsoftonline.com/{tenantId}/oauth2/token` | Retrieve OAuth2 access token using certificate-based client credentials |
| `https://graph.microsoft.com/v1.0/groups`                   | Search Teams-enabled groups                                             |
| `https://graph.microsoft.com/v1.0/groups/{groupId}`         | Update Team metadata (display name, description, visibility)            |
| `https://graph.microsoft.com/v1.0/groups/{groupId}/owners`  | Read Team owners                                                        |
| `https://graph.microsoft.com/v1.0/groups/{groupId}/owners/$ref` | Add and remove Team owners                                          |
| `https://graph.microsoft.com/v1.0/users`                    | Retrieve selectable Entra ID users for owner selection                  |
| `https://graph.microsoft.com/v1.0/teams/{teamId}`           | Retrieve and update Team settings                                       |

### API documentation

- https://learn.microsoft.com/graph/api/overview
- https://learn.microsoft.com/graph/api/group-list
- https://learn.microsoft.com/graph/api/group-update
- https://learn.microsoft.com/graph/api/group-post-owners
- https://learn.microsoft.com/graph/api/group-delete-owners
- https://learn.microsoft.com/graph/api/team-get
- https://learn.microsoft.com/graph/api/team-update
- https://learn.microsoft.com/graph/api/user-list

## Getting help
> :bulb: **Tip:**  
> _For more information on Delegated Forms, please refer to our [documentation](https://docs.helloid.com/en/service-automation/delegated-forms.html) pages_.

## HelloID docs
The official HelloID documentation can be found at: https://docs.helloid.com/