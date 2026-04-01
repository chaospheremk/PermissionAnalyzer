@{
    # Standard severity levels — Warning and Error only.
    # Information-level rules are too noisy for CI enforcement.
    Severity = @('Warning', 'Error')

    # Explicit rules block — documents the rules we care about most.
    # All default rules still run; this block enables these four explicitly.
    Rules = @{
        PSAvoidUsingCmdletAliases            = @{ Enable = $true }
        PSUseApprovedVerbs                   = @{ Enable = $true }
        PSAvoidGlobalVars                    = @{ Enable = $true }
        PSUseDeclaredVarsMoreThanAssignments = @{ Enable = $true }
    }

    ExcludeRules = @(
        # UTF-8 without BOM is the cross-platform standard for PS7.
        'PSUseBOMForUnicodeEncodedFile'

        # Test files use ConvertTo-SecureString -AsPlainText for mock credentials.
        'PSAvoidUsingConvertToSecureStringWithPlainText'
    )
}
