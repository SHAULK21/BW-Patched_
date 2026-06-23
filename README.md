# bw-patcher

Research tool for analyzing and modifying firmware parameters on Brightway-based controllers.

## Important Safety Warning

Modifying device firmware can be dangerous and illegal.

- May void your warranty
- May violate local laws and regulations
- Creates serious safety risks
- Modified devices may be illegal to operate
- You assume all liability for injuries, accidents, and legal consequences

Use at your own risk. This software is for educational and research purposes only.

Read the full [PRINCIPLES.md](PRINCIPLES.md) and [LEGAL_DISCLAIMER.md](LEGAL_DISCLAIMER.md) before using this software.

## How It Works

This tool does not flash the scooter directly. The flashing process requires a two-step workflow:

1. Patching: run this tool locally on your PC. It takes your original downloaded firmware dump, modifies selected parameters, recalculates required CRC checksums, and saves a new `.bin` file.
2. Flashing: manually flash the generated output file using a suitable hardware flashing tool and procedure for your controller.

## Setup

This patcher requires Python and the `keystone-engine` package installed.

Using Poetry:

```bash
poetry install
```

Using pip:

```bash
pip install -r requirements.txt
```

## Supported Models

- Mi4
- Mi4Pro2nd
- Mi4Lite
- Mi5
- Mi5 Plus (region patch)
- Mi5Pro
- Mi5Max
- Mi5Elite
- Ultra4

## Available Modifications

This tool can modify various firmware parameters. The specific parameters available depend on the device model and firmware version.

Common patch codes:

- `rfm`: region free
- `sls=<kmh>`: speed limit sport
- `sld=<kmh>`: speed limit drive
- `rsls`: remove speed limit sport
- `mss=<kmh>`: motor start speed
- `cce`: cruise control enable
- `fdv=<version>`: fake firmware version
- `chk`: fix checksum

`region_free` is also accepted as a compatibility alias for `rfm`.

## Usage

CLI:

```bash
poetry run python -m bwpatcher --help
```

```text
usage: __main__.py [-h] {model} infile outfile patches

positional arguments:
  {model}   Device model, such as mi5plus
  infile    Input firmware file
  outfile   Output firmware file
  patches   Comma-separated list of patches to apply
```

GUI:

```bash
poetry run streamlit run app.py
```

The GUI provides an interactive interface for selecting firmware modifications. A legal disclaimer must be accepted before use.

## Example Usage

Apply the Mi 5 Plus region patch and fix checksum:

```bash
poetry run python -m bwpatcher mi5plus firmware.bin firmware_modified.bin rfm,chk
```

The older alias is also accepted:

```bash
poetry run python -m bwpatcher mi5plus firmware.bin firmware_modified.bin region_free,chk
```

Always maintain raw backups of your original firmware before performing any modifications or manual hardware flashing.

## License

Licensed under CC BY-NC-SA 4.0 (NonCommercial, ShareAlike). See [LICENSE](LICENSE) for full terms.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to this project.

## Disclaimer

This tool is provided for educational and research purposes only. The authors accept no liability for any consequences of using this software. See [LEGAL_DISCLAIMER.md](LEGAL_DISCLAIMER.md) for complete terms.
