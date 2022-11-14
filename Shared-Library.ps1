Function Write-Log {
    <#
        .Synopsis
        Write logs file entries using Configuration Manager formatting.

        .DESCRIPTION
        Internal function used to create and append a target log file
        to record informational, warning, and error entries. This
        function is used by Write-LogMessage which is written to 
        ingest Error Record and Invocation Information PowerShell
        objects and dynamically generate log messages which are then
        passed to this function (Write-Log).

        .INPUTS
        None

        .OUTPUTS
        None

        .NOTES
        None
        
        .COMPONENT
        Shared-Library

        .ROLE
        Logging
        
        .FUNCTIONALITY
        Log handling
    #>
    
    [CmdletBinding()]

    Param (
        
        # Message String message to log
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false,
            ValueFromRemainingArguments=$false,
            HelpMessage="Message to log")]
        [string]
        $Message,

        # Component Originating component source
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false,
            ValueFromRemainingArguments=$false,
            HelpMessage="Component source")]
        [String]
        $Component,

        # Type of message to log (Information, Warning, and Error)
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false,
            ValueFromRemainingArguments=$false,
            HelpMessage="Message type (Info,Warning,Error")]
        [ValidateSet(1,2,3)]
        [String]
        $Type,

        # Thread source for log entry
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false,
            ValueFromRemainingArguments=$false,
            HelpMessage="Thread source")]
        [string]
        $Thread,

        # Source file name and process ID
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false,
            ValueFromRemainingArguments=$false,
            HelpMessage="File source")]
        [String]
        $File
	)

    process {
            
        # Create log file if not exist
        If ((Test-Path $script:logFilePath -PathType Leaf) -eq $false) {
            [void] (New-Item -Path $script:logFilePath -ItemType File)
        }

	    $local:TimeZoneBias = (Get-WmiObject -Query "Select Bias from Win32_TimeZone").Bias -replace '^.*(?=.{3}$)'
        $local:time = Get-Date -Format "HH:mm:ss.fff"
        $local:date = Get-Date -Format "MM-dd-yyyy"
 
        "<![LOG[$Message]LOG]!><time=`"$local:time+$local:TimeZoneBias`" date=`"$date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"$Thread`" file=`"$File`">" | Out-File -FilePath $script:logFilePath -Append -NoClobber -Encoding default
    }
}

function Write-LogMessage {
    <#
        .Synopsis
        Processes InvocationInfo and ErrorRecord objects and calls Write-Log

        .DESCRIPTION
        This function ingests InvocationInfo and ErrorRecord PowerShell objects 
        which are then processed to dynamically create log messages and then
        passed as parameters to Write-Log. 

        .EXAMPLE
        Write-LogMessage -Message "Information log message" -Invocation $MyInvocation

        .EXAMPLE
        Write-LogMessage -Message "Warning log message" -Invocation $MyInvocation -Severity Warning

        .EXAMPLE
        Write-LogMessage -Message "Error log message" -Invocation $MyInvocation -Exception $_ -Severity Error

        .INPUTS
        None

        .OUTPUTS
        None

        .NOTES
        None
        
        .COMPONENT
        Shared Library

        .ROLE
        Logging
        
        .FUNCTIONALITY
        Error Handling
    #>

    [CmdletBinding()]
    param (
        
        # Message to log
        [Parameter(
            Mandatory,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false, 
            ValueFromRemainingArguments=$false,
            HelpMessage="")]
        [string]
        $Message,

        # Invocation object to process
        [Parameter(
             Mandatory,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false, 
            ValueFromRemainingArguments=$false,
            HelpMessage="")]
        [System.Management.Automation.InvocationInfo]
        $Invocation,

        # Exception object to process
        [Parameter(
            Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false, 
            ValueFromRemainingArguments=$false,
            HelpMessage="")]
        [System.Management.Automation.ErrorRecord]
        $Exception,

        # Severity of the log entry (Information, Warning, Error)
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false, 
            ValueFromRemainingArguments=$false,
            HelpMessage="")]
        [ValidateSet('Information','Warning','Error')]
        [string]
        $Severity
    )

    Begin {
        # Initialize Messages array
        [array]  $local:Messages = @()

        # Initialize Component variable 
        [string] $local:Component = [string]::Empty

        # Initialize Type variable 
        [string] $local:Type = [string]::Empty

        # Initialize Thread variable 
        [string] $local:Thread = [string]::Empty

        # Initialize File variable 
        [string] $local:File = [string]::Empty

        # Initialize ExceptionMessage variable 
        [string] $local:ExceptionMessage = [string]::Empty

        # Initialize Line variable 
        [string] $local:Line = [string]::Empty

        # Initialize Trace variable 
        [string] $local:Trace = [string]::Empty
    }

    Process {
        # Convert Severity string to Type integer
        switch ($Severity) {
            'Information' {
                $local:Type = 1
            }

            'Warning' {
                $local:Type = 2
            }
            
            'Error' {
                $local:Type = 3
            }

            default {
                $local:Type = 1
            }
        }

        # Assert $MyInvocation scope (Main script or function)
        if (Test-Path -Path $Invocation.InvocationName) {
            # Script Scope 
            $local:Component = "Main-Script"
            $local:File = "$($Invocation.MyCommand.Name):$($Invocation.ScriptLineNumber)"
        } else {
            # Function Scope
            $local:Component = $Invocation.InvocationName
            $local:File = "$($Invocation.PSCommandPath | Split-Path -Leaf):$($Invocation.ScriptLineNumber)"
        }

        # Assert $Exception contains an Error Record object
        if ($Exception) {
            # Error record detected

            # Build parameters to pass Write-Log
            $local:Type = $local:Type
            $local:Thread = $PID
            $local:ExceptionMessage = $Exception.Exception.Message
            $local:Line = $Exception.InvocationInfo.Line.Trim()
            $local:Trace = $Exception.ScriptStackTrace

            # Build $Messages array to process
            [array] $local:Messages = $Message,$local:ExceptionMessage,$trace,$Line

            # Call Write-Log
            foreach ($local:Message in $local:Messages) {
                Write-Log -Message $local:Message -Component $Component -Type $Type -Thread $Thread -File $File
            }

            # Exit function
            return
        }

        # Assert $Invocation contains an Invocation Info object
        if ($Invocation) {
            # Infovation Info detected

            # Build parameters to pass to Write-Log
            $local:Message = $Message
            $local:Type = $Type
            $local:Thread = $PID
            
            # Call Write-Log
            Write-Log -Message $local:Message -Component $Component -Type $Type -Thread $Thread -File $File
        }
    }
}

Function Set-RegistryKeyValue {
    <#
        .Synopsis
        Creates or sets a registry key value

        .DESCRIPTION
        Creates or sets a registry key value on existing registry key path

        .EXAMPLE
        Set-RegistryKeyValue -Hive HKLM -Path 'Softare\Microsoft' -Name 'foo' -Value 'bar' -Type String

        .INPUTS
        None

        .OUTPUTS
        None

        .NOTES
        None
        
        .COMPONENT
        Shared Library

        .ROLE
        Registry worker
        
        .FUNCTIONALITY
        Registry
    #>

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false, 
            ValueFromRemainingArguments=$false
        )]
        [ValidateSet('HKLM','HKCU','HKR','HKU')]
        [String]
        $Hive,

        [Parameter(
            Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false, 
            ValueFromRemainingArguments=$false
        )]
        [String]
        $Path,

        [Parameter(
            Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false, 
            ValueFromRemainingArguments=$false
        )]
        [String]
        $Name,

        [Parameter(
            Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false, 
            ValueFromRemainingArguments=$false
        )]
        [String]
        $Value,

        [Parameter(
            Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false, 
            ValueFromRemainingArguments=$false
        )]
        [String]
        [ValidateSet('String','ExpandString','Binary','DWord','Qword')]
        $Type
    )

    Process {
        try {
            [void] (New-ItemProperty -Path "$($Hive):\$Path" -Name "$($Name)" -Value "$($Value)" -PropertyType $Type -Force -ErrorAction Stop)
        } catch {
            Write-LogMessage -Message "Failed to set registry key value" -Invocation $MyInvocation -Exception $_ -Severity Error
        }
    }
}