# cp2xlsx

cp2xlsx converts compressed file from [ShowPolicyPackage](https://github.com/CheckPointSW/ShowPolicyPackage) into neet xlsx table.
Supported policies:
* Global firewall
* Domain firewall
* NAT
* Threat prevention

## Usage

```
cp2xlsx [-h] [-eg | -neg] [-sm | -nsm] [-sg {no,policy,all}] file
```

### Where:
* ```-h, --help```: show help message and exit
* ```-eg, --export-global```: export global firewall rules
* ```-neg, --no-export-global```: don't export global firewall rules
* ```-sm, --show-members```: show group members
* ```-nsm, --no-show-members```: don't show group members
* ```-sg {no,policy,all}, --save-groups {no,policy,all}```: save group members to files (default: no)
    * policy: save groups only used in the policy
    * all: save all groups
* ```file```: path to compressed file you got from [ShowPolicyPackage](https://github.com/CheckPointSW/ShowPolicyPackage)

### Output
* [PackageName].xlsx file

If ```--save-groups``` specified:

* [PackageName]/*.txt files

## Building
To use cp2xlsx without installed Python interpreter you can build cp2xlsx with [PyInstaller](https://github.com/pyinstaller/pyinstaller). Releases for Windows located [here](https://github.com/a5trocat/cp2xlsx/releases).

## See also
* https://github.com/CheckPointSW/ShowPolicyPackage
* https://github.com/pyinstaller/pyinstaller
