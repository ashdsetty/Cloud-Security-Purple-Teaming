# Cloud-Security-Purple-Teaming

## Introduction

In this paper, we will go over many different aspects to red teaming and blue teaming in regards to cloud security, mainly Microsoft Azure. We will tackle the stages of an attack lifecycle that a hacker would use to attack Microsoft Azure as well as the ways to detect and prevent these attacks. We will also go over how to set up logging and auditing so that detection is possible and much easier to accomplish in Microsoft Azure. 

# Azure Hacking

## Iniitial Access

### Background - Azure vs ASDK

Microsoft has an on-premise Azure environment called Azure Stack which is meant primarily for enterprise usage. There is also a version called Azure Stack Development Kit (ASDK) which is free. 

Main Differences: 
- Scalability
  - ASDK runs on a single instance with limited resources and all of its roles run as separate VMs handled by Hyper-V. This causes some internal architectural differences.
- ASDK doesn’t run the latest software as Azure does, but is a couple of versions behind.
- Compared to Azure, ASDK has a very limited number of features.

#### Azure Stack Overview
![Azure Stack Overview](https://research.checkpoint.com/wp-content/uploads/2020/01/azure2.png)

##### [Infrastructure Roles](https://docs.microsoft.com/en-us/azure-stack/asdk/asdk-architecture?view=azs-2005) :

Main Virtual Machines:

* ARM Layer: AzS-WAS01, AzS-WASP01
* RP Layer + Infrastructure Control Layer: AzS-XRP01

Issues: 

Service Fabric Explorer is a web tool pre-installed in the machine that takes the role of the RP and Infrastructure Control Layer. This enables us to view the internal services which are built as Service Fabric Applications, which is located in the RP layer. Some of the URLs of the services from the SFE don't require authentication, which can lead to vulnerabilities in the entire stack. 

### Vulnerabilities

1. [CVE-2019-1234](https://nvd.nist.gov/vuln/detail/CVE-2019-1234) - spoofing

If exploited, the issue would have enabled a remote hacker to unauthorizedly access screenshots and sensitive information of any virtual machine running on Azure infrastructure — it doesn't matter if they're running on a shared, dedicated or isolated virtual machines.

2. [CVE-2019-1372](https://nvd.nist.gov/vuln/detail/CVE-2019-1372#:~:text=An%20remote%20code%20execution%20vulnerability,the%20context%20of%20NT%20AUTHORITY%5C) - remote code execution

An attacker who successfully exploited this vulnerability could allow an unprivileged function run by the user to execute code in the context of NT AUTHORITY\system thereby escaping the Sandbox.

### [Recon (Outsider)](https://o365blog.com/aadkillchain/)

[Azure AD Recon (AADInternals)](https://o365blog.com/aadinternals/)

Install this powershell module to perform recon.

Commands: 
```
Install-Module AADInternals
Import-Module AADInternals
Invoke-AADIntReconAsOutsider -DomainName company.com | Format-Table
Invoke-AADIntUserEnumerationAsOutsider -UserName "user@company.com

# Get login information for a domain
Get-AADIntLoginInformation -Domain company.com
```

### Intrusion - Execution

#### Password Spraying

[Password Spraying  Github Link](https://github.com/nickvangilder/Office-365-Password-Spray)

https://github.com/dafthack/MailSniper

Target a group of Office 365 accounts and use a generalized password list (created through python script). 

Use the accounts found through the Outsider Recon Powershell scripts.

Password Spraying Scripts: 

https://github.com/mysoc/detection-sandbox/blob/master/pspray.ps1

https://github.com/mysoc/detection-sandbox/blob/master/O365-spray.ps1

#### User Enumeration
```
Invoke-AADIntUserEnumerationAsOutsider -UserName "user@company.com"
```
You can use a text file of users (userlist) : 
```
Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider
```

### [Recon (Guest)](https://o365blog.com/post/quest_for_guest/)
Use guest account from password spraying

```
# Get tenant details
Get-AADIntTenantDetails

# Prompt for credentials and retrieve & store access token to cache
Get-AADIntAccessTokenForAADGraph -SaveToCache

# Prompt for credentials and save the token to cache
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# List the user's tenants
Get-AADIntAzureTenants
```

Stage 1: If we know the user id or upn of any user of the tenant, we can list all the groups (including teams and roles) the user is member of. As a result, we now know the ids of those groups, and we can retrieve the list of members of those groups.

```
# Invoke the user enumeration
$results = Invoke-AADIntUserEnumerationAsGuest -GroupMembers -Manager -Subordinates -Roles
# List group information
$results.Groups | Select-Object displayName,id,membershiprule,description
$results.Groups | Select-Object displayName,id,members
```
Now we have the list of all external users of the tenant

Stage 2: Now we can retrieve the same information (groups and their members) for each user found at stage 1!
```
# Invoke the user enumeration for the known user including group members
$results = Invoke-AADIntUserEnumerationAsGuest -UserName "user@company.com" -GroupMembers -Manager -Subordinates -Roles
# List group information
$results.Groups | Select-Object displayName,id,membershiprule,description

# Listing the group information reveals another typical configuration. 
There is a dynamic group for all organisation members: this allows guest users to access all users of the tenant

# List role information
$results.Roles | Select-Object id,members
```
#### Phishing - Azure App 

##### Resources

https://github.com/mdsecactivebreach/o365-attack-toolkit

https://www.mdsec.co.uk/2019/07/introducing-the-office-365-attack-toolkit/

https://www.youtube.com/watch?v=JZjrvpacfDY

1. Background - requires victim to own a web application hosted by an Azure tenant. 

2. Spear phishing campaign

3. The link in the email directs the user to the attacker-controlled website (e.g., https://myapp.malicious.com) which seamlessly redirects the victim to Microsoft’s login page. The authentication flow is handled entirely by Microsoft, so using multi-factor authentication isn’t a viable mitigation.

Once the user logs into their O365 instance, a token will be generated for the malicious app and the user will be prompted to authorize and give it the permissions it needs. 

![token](https://blogvaronis2.wpengine.com/wp-content/uploads/2020/03/3.png)

4. On the attacker’s side, here are the MS Graph API permissions that are being requested:

![Permissions Requested by Malicious App](https://blogvaronis2.wpengine.com/wp-content/uploads/2020/03/4.png)

The attacker has control over the application’s name and the icon. The URL is a valid Microsoft URL and the certificate is valid.

Under the application’s name, however, is the name of the attacker’s tenant and a warning message, neither of which can be hidden. An attacker’s hope is that a user will be in a rush, see the familiar icon, and move through this screen as quickly and thoughtlessly as they’d move through a terms of service notice.

By clicking “Accept”, the victim grants the aplication the permissions on behalf of their user—i.e., the application can read the victim’s emails and access any files they have access to.

This step is the only one that requires the victim’s consent — from this point forward, the attacker has complete control over the user’s account and resources.

After granting consent to the application, the victim will be redirected to a website of our choice. A nice trick can be to map the user’s recent file access and redirect them to an internal SharePoint document so the redirection is less suspicious.

### Post Intrusion - Persistance forward

1. Reconnaissance (enumerating users, groups, objects in the user’s 365 tenant)

```
# Get tenant details
Get-AADIntTenantDetails
```

2. Spear phishing (internal-to-internal)

3. Stealing files and emails from Office 365

4. API metadata: 
  - gain access to metadata for every single user in the organization
  - shows the victim’s calendar events. Can also set up meetings on their behalf, view existing meetings, and even free up time in their day by deleting meetings they set in the future.
  - see any file the user accessed in OneDrive or SharePoint. You can also download or modify files (malicious macros for persistence).
  - When accessing a file via this API, Azure generates a unique link. This link is accessible by anyone from any location—even if the organization does not allow anonymous sharing links for normal 365 users.
  - complete access to our victim’s email. We can see the recipients of any message, filter by high priority emails, send emails (i.e., spear phish other users), and more.
  - By reading the user’s emails, you can identify the most common and vulnerable contacts, send internal spear-phishing emails that come from our victim, and infect his peers. You can also use the victim’s email account to exfiltrate data that you find in 365.
  - Microsoft also provides insights about the victim’s peers using the API. The peer data could be used to pinpoint other users that the victim had the most interaction with
  - modify the user’s files with the right permissions. (potential: One option is to turn the malicious Azure app into ransomware that remotely encrypts files that the user has access to on SharePoint and OneDrive)

5. [AWS Lambda](https://danielgrzelak.com/backdooring-an-aws-account-da007d36f8f9)

6. [Azure Persistance](https://blog.netspi.com/maintaining-azure-persistence-via-automation-accounts/) - Adds an Automation Account with excessive privileges that can be used to add new accounts (with Subscription Owner permissions) to AzureAD via a single POST request.

  Process
  - Create a new Automation Account
  - Import a new runbook that creates an AzureAD user with Owner permissions for the subscription*
  - Sample runbook for this Blog located here – https://github.com/NetSPI/MicroBurst
  - Add the AzureAD module to the Automation account
  - Update the Azure Automation Modules
  - Assign “User Administrator” and “Subscription Owner” rights to the automation account
  - Add a webhook to the runbook
  - Eventually lose your access…
  - Trigger the webhook with a post request to create the new user


### Resources

* https://thehackernews.com/2020/01/microsoft-azure-vulnerabilities.html
* https://medium.com/@kamran.bilgrami/ethical-hacking-lessons-building-free-active-directory-lab-in-azure-6c67a7eddd7f
* https://research.checkpoint.com/2020/remote-cloud-execution-critical-vulnerabilities-in-azure-cloud-infrastructure-part-i/
* https://research.checkpoint.com/2020/remote-cloud-execution-critical-vulnerabilities-in-azure-cloud-infrastructure-part-ii/
* https://rhinosecuritylabs.com/cloud-security/common-azure-security-vulnerabilities/
* https://portswigger.net/daily-swig/spotlight-shone-on-microsoft-azure-vulnerability
* https://www.darkreading.com/cloud/how-attackers-could-use-azure-apps-to-sneak-into-microsoft-365/d/d-id/1337399
* https://www.youtube.com/watch?v=JEIR5oGCwdg
* https://danielzstinson.wordpress.com/cloud-computing-may-not-be-as-secure-as-you-would-like-to-believevulnerabilities-in-azure-part-2/
* https://www.darkreading.com/cloud/how-attackers-could-use-azure-apps-to-sneak-into-microsoft-365/d/d-id/1337399
* https://docs.microsoft.com/en-us/azure/security-center/security-center-alerts-overview
* https://docs.microsoft.com/en-us/azure/security/fundamentals/threat-detection
* https://www.varonis.com/blog/using-malicious-azure-apps-to-infiltrate-a-microsoft-365-tenant/
* https://www.exfiltrated.com/research/HackingTheClouds.pdf
* https://danielgrzelak.com/backdooring-an-aws-account-da007d36f8f9
* https://cyberx.tech/hacking-lab/
* https://blog.netspi.com/maintaining-azure-persistence-via-automation-accounts/

# Office 365 Hacking

## Vulnerabilities

1. [SAML](https://www.pindrop.com/blog/office-365-bug-allowed-attackers-to-login-to-virtually-any-account/) - A vulnerability in Microsoft Office 365 SAML Service Provider implementation allowed for cross domain authentication bypass affecting all federated domains. An attacker exploiting this vulnerability could gain unrestricted access to a victim’s Office 365 account, including access to their email, files stored in OneDrive etc.

## Resources

* https://www.coreview.com/blog/office-365-vulnerabilities-hacks-and-attacks/
* https://www.pindrop.com/blog/office-365-bug-allowed-attackers-to-login-to-virtually-any-account/
* https://www.fireeye.com/blog/threat-research/2020/07/insights-into-office-365-attacks-and-how-managed-defense-investigates.html
* https://www.darkreading.com/cloud/how-attackers-could-use-azure-apps-to-sneak-into-microsoft-365/d/d-id/1337399
* https://o365blog.com/aadkillchain/

# Detection - Filebeat

## Create an Event Hub

1. Create a Resource Group (if necessary): standard options, note down the name

2. Create an Event Hub: Create a Resource -> Event Hubs -> Add (Create event hubs namespace)

- select correct subscription, resource group from step 1, standard options

- note down name

3. Go to Event Hubs Namespace page, select Event Hubs in the left menu, at the top of the window, click + Event Hub

- note down name, create

## Check Permissions and Get Connection String

1. Go to event hubs namespace -> Setting -> Shared Access Policies: Under Claims, make sure that the manage permission is enabled

![namespace](https://docs.microsoft.com/en-us/azure/connectors/media/connectors-create-api-azure-event-hubs/event-hubs-namespace.png)

2. Under Policy, click on RootManageSharedAccessKey: Note down the primary key connection string

![connection string](https://docs.microsoft.com/en-us/azure/connectors/media/connectors-create-api-azure-event-hubs/find-event-hub-namespace-connection-string.png)

## Logic App

### Connect to your Event Hub

When asked to connect to event hub

Retrieve the following information by following these instructions:
- Go to Log Analytics Workspace -> Settings -> Agents Management
- Note Down Workspace ID and Primary Key

![workspace](https://user-images.githubusercontent.com/63748134/95359627-622b7b00-0898-11eb-843f-0dc6be1484e4.png)

When asked for connection to event hub. click manually enter connection information, use the following fields
- Connection Name: Custom name
- Workspace Key: Same key retrieved from earlier
- Workspace ID: Same ID retrieved from earlier

### Export Activity Log to Event Hub

1. Go to Activity Log

2. Diagnostic Settings -> Add Diagnostic Setting -> Select all logs 

3. Click Archive to storage account -> Select your preferred storage account

4. Click Stream to an event hub -> Input namespace -> input event hub name (insights-operational-logs) -> input policy name (RootManageSharedAccessKey)

![activity log](https://user-images.githubusercontent.com/63748134/95362630-59d53f00-089c-11eb-973c-465ad66571df.png)

5. Save

### Add Event Hubs Trigger

1. Create a blank logic app, this will open up the logic app designer

2. In the search box, enter event hubs

![event hubs](https://docs.microsoft.com/en-us/azure/connectors/media/connectors-create-api-azure-event-hubs/find-event-hubs-trigger.png)

3. Provide the info for the trigger:
- event hub name: insights-operational-logs
- content type: application/json

![example](https://docs.microsoft.com/en-us/azure/connectors/media/connectors-create-api-azure-event-hubs/event-hubs-trigger.png)

### Add Event Hubs Parse Json

1. Add new step in logic app designer

2. Search parse json (Under Data Operations)  -> Click Parse Json action -> Enter Body in content field

![data operations](https://user-images.githubusercontent.com/63748134/95357350-c39e1a80-0895-11eb-8b91-87656dcfca69.png)


3. For the schema, use this script: 

<details><summary>CLICK ME</summary>
<p>

#### Copy this script, add to Body in Parse Json field

```python
{
    "properties": {
        "body": {
            "properties": {
                "ContentData": {
                    "type": "string"
                },
                "Properties": {
                    "properties": {
                        "ProfileName": {
                            "type": "string"
                        },
                        "x-opt-enqueued-time": {
                            "type": "string"
                        },
                        "x-opt-offset": {
                            "type": "string"
                        },
                        "x-opt-sequence-number": {
                            "type": "number"
                        }
                    },
                    "type": "object"
                },
                "SystemProperties": {
                    "properties": {
                        "EnqueuedTimeUtc": {
                            "type": "string"
                        },
                        "Offset": {
                            "type": "string"
                        },
                        "PartitionKey": {},
                        "SequenceNumber": {
                            "type": "number"
                        }
                    },
                    "type": "object"
                }
            },
            "type": "object"
        },
        "headers": {
            "properties": {
                "Cache-Control": {
                    "type": "string"
                },
                "Content-Length": {
                    "type": "string"
                },
                "Content-Type": {
                    "type": "string"
                },
                "Date": {
                    "type": "string"
                },
                "Expires": {
                    "type": "string"
                },
                "Location": {
                    "type": "string"
                },
                "Pragma": {
                    "type": "string"
                },
                "Retry-After": {
                    "type": "string"
                },
                "Timing-Allow-Origin": {
                    "type": "string"
                },
                "Transfer-Encoding": {
                    "type": "string"
                },
                "Vary": {
                    "type": "string"
                },
                "X-AspNet-Version": {
                    "type": "string"
                },
                "X-Powered-By": {
                    "type": "string"
                },
                "x-ms-request-id": {
                    "type": "string"
                }
            },
            "type": "object"
        }
    },
    "type": "object"
}
```

</p>
</details>

![parse json](https://user-images.githubusercontent.com/63748134/95356891-2d69f480-0895-11eb-9a54-498dd04d883f.PNG)

### Compose

1. Add New step -> Data Operations -> Actions -> Compose 

2. Select Body

![compose](https://user-images.githubusercontent.com/63748134/95357737-3f986280-0896-11eb-836b-057fa09afbf1.PNG)

### Send Data

1. Add New Step -> Search Data Collector -> CLick on Send Data (Azure Log Analytics Data Collector)

![data collector](https://user-images.githubusercontent.com/63748134/95357976-871eee80-0896-11eb-9c62-d6697d7a9f72.PNG)

2. Enter Fields: Outputs under JSON Request Body, Create a name for logs, Add time as a new parameter 

![send data](https://user-images.githubusercontent.com/63748134/95358044-9b62eb80-0896-11eb-86b1-6b6d9bd4cc0b.PNG)

3. Click Save

4. Run to test if it works

## Resources

* https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-eventhub.html
* https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-collect-tenants#:~:text=In%20the%20Azure%20portal%2C%20select%20Monitor%20%3E%20Activity%20Log.,an%20event%20hub%20check%20box.
* https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-create
* https://docs.microsoft.com/en-us/azure/connectors/connectors-create-api-azure-event-hubs
