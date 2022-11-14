<#
function Verb-Noun {
#
    .Synopsis
    Short description

    .DESCRIPTION
    Long description

    .EXAMPLE
    Example of how to use this cmdlet

    .EXAMPLE
    Another example of how to use this cmdlet

    .INPUTS
    Inputs to this cmdlet (if any)

    .OUTPUTS
    Output from this cmdlet (if any)

    .NOTES
    General notes
        
    .COMPONENT
    The component this cmdlet belongs to

    .ROLE
    The role this cmdlet belongs to
        
    .FUNCTIONALITY
    The functionality that best describes this cmdlet
#

    [CmdletBinding()]
    [OutputType([])]

    Param (
        # Param1 help description
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false,
            ValueFromRemainingArguments=$false,
            ValueFromRemainingArguments=$false,
            HelpMessage="")]
        [ValidateSet("sun","moon","earth")]
        [string]
        $Param1,

        # Param2 help description
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false,
            ValueFromRemainingArguments=$false,
            HelpMessage="")]
        [ValidateSet("sun","moon","earth")]
        [STRING]
        $Param2
    )

    Begin {
    }

    Process {
    }
    
    End{
    }
}
#>

Function Write-Log {
    <#
        .Synopsis
        Short description

        .DESCRIPTION
        Long description

        .EXAMPLE
        Example of how to use this cmdlet

        .EXAMPLE
        Another example of how to use this cmdlet

        .INPUTS
        Inputs to this cmdlet (if any)

        .OUTPUTS
        Output from this cmdlet (if any)

        .NOTES
        General notes
        
        .COMPONENT
        The component this cmdlet belongs to

        .ROLE
        The role this cmdlet belongs to
        
        .FUNCTIONALITY
        The functionality that best describes this cmdlet
    #>
    
    [CmdletBinding()]

    Param (
        
        # Message help description
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false,
            ValueFromRemainingArguments=$false,
            HelpMessage="")]
        [string]
        $Message,

        # Component help description
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false,
            ValueFromRemainingArguments=$false,
            HelpMessage="")]
        [String]
        $Component,

        # Type help description
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false,
            ValueFromRemainingArguments=$false,
            HelpMessage="")]
        [String]
        $Type,

        # Thread help description
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false,
            ValueFromRemainingArguments=$false,
            HelpMessage="")]
        [string]
        $Thread,

        # File help description
        [Parameter(Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false,
            ValueFromRemainingArguments=$false,
            HelpMessage="")]
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
        Example of how to use this cmdlet

        .EXAMPLE
        Another example of how to use this cmdlet

        .INPUTS
        Inputs to this cmdlet (if any)

        .OUTPUTS
        Output from this cmdlet (if any)

        .NOTES
        General notes
        
        .COMPONENT
        The component this cmdlet belongs to

        .ROLE
        The role this cmdlet belongs to
        
        .FUNCTIONALITY
        The functionality that best describes this cmdlet
    #>

    [CmdletBinding()]
    param (

        [Parameter(
            Mandatory,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false, 
            ValueFromRemainingArguments=$false,
            HelpMessage="")]
        [string]
        $Message,

        [Parameter(
             Mandatory,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false, 
            ValueFromRemainingArguments=$false,
            HelpMessage="")]
        [System.Management.Automation.InvocationInfo]
        $Invocation,

        [Parameter(
            Mandatory=$false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false, 
            ValueFromRemainingArguments=$false,
            HelpMessage="")]
        [System.Management.Automation.ErrorRecord]
        $Exception,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline=$false,
            ValueFromPipelineByPropertyName=$false, 
            ValueFromRemainingArguments=$false
        )]
        [ValidateSet('Information','Warning','Error')]
        [string]
        $Severity
    )

    begin {
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

    process {
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

Function Set-Reg {
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

    try {
        [void] (New-ItemProperty -Path "$Hive\$Path" -Name "$($Name)" -Value "$($Value)" -PropertyType $Type -Force -ErrorAction Stop)
    } catch {
        Write-LogMessage -Message "Failed to set registry key value" -Invocation $MyInvocation -Exception $_ -Severity Error
    }
}