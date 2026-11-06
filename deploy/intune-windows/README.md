# Intune and GPO recipes for Windows

The steps are in [docs/fleet.md](../../docs/fleet.md#intune-windows) (and
[GPO](../../docs/fleet.md#gpo)).

| File | Purpose |
| --- | --- |
| `fleet-files.ps1` | Intune platform script, or a GPO startup script. Run it elevated, before the MSI. It makes `C:\ProgramData\saiife` and `etc` with the permissions saiife expects, then writes the fleet files. It refuses a junction or a folder a user made. |
| `detect.ps1` | Win32 app detection: exit 0 with a line of output when the package and the service are there, exit 1 otherwise. |
| `discovery.ps1` | Custom compliance discovery: one line of JSON with `saiife_installed` and `saiife_doctor_exit`. Only reads state. |
| `rules.json` | The compliance rules for that JSON, with `en_US` remediation strings. |

The `.intunewin` files come from a release (`saiife-<version>-<arch>.intunewin`), or from
`scripts/package-windows/build.ps1`.

All scripts are ASCII only: Windows PowerShell 5.1 reads a file without a byte order mark
in the system code page.
