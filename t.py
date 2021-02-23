import subprocess

def run(cmd):
    completed = subprocess.run(["powershell", "-Command", cmd], capture_output=True)
    return completed


if __name__ == '__main__':
    hello_command = "$Keys = Get-Item -Path HKLM:\Software\RegisteredApplications | Select-Object -ExpandProperty property"
    hello_info = run(hello_command)
    hello_command = "$Product = $Keys | Where-Object {$_ -Match 'Outlook.Application.'}"
    hello_info = run(hello_command)
    hello_command = "$OfficeVersion = ($Product.Replace('Excel.Application.',"")+'.0')"
    hello_info = run(hello_command)
    hello_command = "Write-Host $OfficeVersion"
    hello_info = run(hello_command)


    if hello_info.returncode != 0:
        print("An error occured: %s", hello_info.stderr)
    else:
        print("Hello command executed successfully!")


