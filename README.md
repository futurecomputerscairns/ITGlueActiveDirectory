# ITGlue - Active Directory
This is a project to import Active Directory and domain information, based on the default fields that are present for Active Directory flexible assets in ITGlue

## Prerequisites 

Powershell 3.0 is required for this script to run.

[Powershell API Wrapper](https://github.com/itglue/powershellwrapper)

**Due to requirements I have in my environments, I needed to manually download the module and place into C:\Temp\ITGlue\Modules**

Edit line #50 to 'Import-Module ITGlueAPI' and add a line above containing 'Install-Module ITGlueAPI'


## Running the script

```
.\ITGlueActiveDirectory.ps1 -Organisation 'Contoso Ltd' -Key "ITG.[YOURAPIKEYHERE]"
```

