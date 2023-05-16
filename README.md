# cp2xlsx

cp2xlsx converts compressed file from [ShowPolicyPackage](https://github.com/CheckPointSW/ShowPolicyPackage) into neet xlsx table.
Supported policies:
* Global firewall
* Domain firewall
* NAT
* Threat prevention

## Usage

```
cp2xlsx [-h] [-st] [-eg | -neg] [-sm | -nsm] file
```

### Where:
* ```-h, --help```: show help message and exit
* ```-st, --single-thread```: use single thread
* ```-eg, --export-global```: export global firewall rules
* ```-neg, --no-export-global```: don't export global firewall rules
* ```-sm, --show-members```: show group members
* ```-nsm, --no-show-members```: don't show group members
* ```file```: path to compressed file you got from [ShowPolicyPackage](https://github.com/CheckPointSW/ShowPolicyPackage)

### Output
[PackageName].xlsx file

## Building
To use cp2xlsx without installed Python interpreter you can build cp2xlsx with [PyInstaller](https://github.com/pyinstaller/pyinstaller). Releases for Windows located [here](https://github.com/a5trocat/cp2xlsx/releases).

## See also
* https://github.com/CheckPointSW/ShowPolicyPackage
* https://github.com/pyinstaller/pyinstaller
