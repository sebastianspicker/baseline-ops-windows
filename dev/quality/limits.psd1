# Numeric metric ceilings for the PowerShell and Rust code-quality gates.
# A finding is reported when a measured value is strictly greater than its limit.
@{
  SchemaVersion = 1
  PowerShell = @{
    FunctionNloc = 49
    FunctionCcn = 7
    FunctionParameters = 8
    FileNloc = 499
  }
  Rust = @{
    FunctionNloc = 49
    FunctionCcn = 7
    FunctionParameters = 8
    FileNloc = 499
  }
}
