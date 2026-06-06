# Command Injection Examples
# CWE-078: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

# =============== BAD EXAMPLE ===============
# UNSAFE: Direct use of user input in shell command
def bad_command_execution(request):
    import subprocess
    action = request.POST.get('action', '')
    # Vulnerability: User input directly passed to shell command
    subprocess.call(['application', action], shell=True)


# =============== GOOD EXAMPLE ===============
# SAFE: Use allowlist for valid commands
COMMANDS = {
    "list": "ls",
    "stat": "stat",
    "backup": "backup.sh"
}

def good_command_execution(request):
    import subprocess
    action = request.POST.get('action', '')
    
    # Security: Validate against allowlist
    if action not in COMMANDS:
        raise ValueError("Invalid action")
    
    # Safe: Only allowed commands are executed
    subprocess.call([COMMANDS[action]])


# =============== BETTER EXAMPLE ===============
# SAFER: Use subprocess with list argument (no shell)
def better_command_execution(request):
    import subprocess
    action = request.POST.get('action', '')
    
    # Security: Strict allowlist validation
    allowed_actions = ["list", "stat", "backup"]
    if action not in allowed_actions:
        raise ValueError(f"Invalid action: {action}")
    
    # Safe: No shell=True, no string concatenation
    subprocess.run(["/usr/bin/myapp", action])
