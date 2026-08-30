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

1. Patching: run this tool locally on your PC. It takes your original firmware package, modifies selected parameters, recalculates required CRC checksums, and can extract the embedded MCU image.
2. Flashing: manually flash the generated image using a suitable hardware flashing tool and a procedure verified for your controller.

For Mi5 Plus, the OTA package contains a signed trailer. The `img` operation strips that validated trailer and preserves the complete firmware prefix; it does **not** synthesize a new 64 KiB image.

## Setup

This patcher requires Python and the `keystone-engine` / `capstone` packages installed.

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
- Mi5 Plus (verified speed hook; region patch intentionally disabled)
- Mi5Pro
- Mi5Max
- Mi5Elite
- Ultra4

## Available Modifications

This tool can modify various firmware parameters. The specific parameters available depend on the device model and firmware version.

Common patch codes:

- `sls=<kmh>`: speed limit sport API; on Mi5 Plus this currently targets the verified common active-profile speed hook
- `sld=<kmh>`: speed limit drive API; on Mi5 Plus this currently targets the verified common active-profile speed hook
- `slp=<kmh>`: pedestrian speed API
- `rsls`: remove sport speed limit API
- `mss=<kmh>`: motor start speed
- `cce`: cruise control enable
- `rfm`: region free where a model-specific verified patch exists
- `fdv=<version>`: fake firmware version where implemented
- `chk`: fix checksum where supported by the model
- `img`: Mi5 Plus only — extract the embedded MCU image from the signed OTA container

For Mi5 Plus specifically, `rfm/region_free` is intentionally refused until a region table is verified against the original BIN. No blind writes are performed at `0x3440` or `0x3C80`.

## Mi5 Plus OTA → MCU image conversion

The reference Mi5 Plus OTA package is 125371 bytes and contains a binary trailer marker `MI EF TFOTA` at file offset `0x1E480`, followed by the model identifier and X.509 certificate material. The converter validates this trailer, verifies the existing CRC-16, then keeps the exact prefix before the trailer as the embedded image.

For the reference package:

```text
OTA package size:      125371 (0x1E9BB)
Embedded image end:    0x1E480
Embedded image size:   124032 bytes (0x1E480)
OTA trailer size:      1339 bytes (0x53B)
```

The image is not padded to 64 KiB and no vector table is fabricated. The original firmware-relative addresses, including the confirmed speed hook at `0x5C76`, stay unchanged.

### CLI examples

Patch speed and output the OTA container:

```bash
poetry run python -m bwpatcher mi5plus firmware.bin firmware_patched_35.bin sld=35
```

Patch speed and then extract the embedded MCU image:

```bash
poetry run python -m bwpatcher mi5plus firmware.bin mi5plus_flash_image_35.bin sld=35,img
```

Extract the MCU image without changing firmware bytes:

```bash
poetry run python -m bwpatcher mi5plus firmware.bin mi5plus_flash_image.bin img
```

The `img` operation refuses conversion when the OTA trailer or container CRC cannot be validated. An already-extracted image is accepted only when the confirmed Mi5 Plus speed hook can still be located.

## Xiaomi 5 Plus Reverse Engineering

The current Mi5Plus work is based on the original OTA package used during RE:

- Size: `125371` bytes
- SHA-256: `bdcec9c57c53279a19c28e437003e06e11f441170a349f94f7fdb140edd33cf4`
- Flash base: `0x08000000`
- Confirmed speed hook: file `0x5C74`, MCU `0x08005C74`
- Hook bytes: `AB 49 78 7A 08 80`
- Patch instruction: file `0x5C76`, `78 7A` → `XX 20` (`MOVS r0,#XX`)
- Runtime destination: `0x20000234`
- 5 Plus CRC: CRC-16-CCITT over `[0x100:0x8D00)`, stored big-endian at `0xB0`

The repository deliberately distinguishes bytecode facts from semantic guesses. In particular, the previously claimed `0x20001E2C = 0/1/2` mode mapping, `0x0800A412` writer, `0x08005834` default-mode write, `0x3440/0x3C80` region tables, and the high-level meaning `0x200002E5 == 1 → 435` are not treated as verified patch semantics.

## Reverse-Engineering Tools

The repository includes a CFG-aware Thumb/Thumb-2 analysis layer:

```bash
python tools/analyze_mi5plus.py path/to/mcu_xiaomi.scooter.5plus.bin
```

Inspect a particular RAM/Flash target:

```bash
python tools/analyze_mi5plus.py firmware.bin --target 0x20001E2C --json report.json
```

The analyzer:

- validates the raw input and computes SHA-256;
- reads the Cortex-M vector-style data where applicable;
- follows reachable Thumb/Thumb-2 control flow to reduce literal-pool false positives;
- resolves PC-relative literal references;
- searches bounded data-flow for memory readers/writers;
- reports mode-like comparisons for `0/1/2` without automatically naming them Eco/Drive/Sport;
- detects the confirmed 5 Plus speed hook;
- never modifies the input firmware.

The authoritative methodology and current evidence table are in [docs/MI5PLUS_RE.md](docs/MI5PLUS_RE.md).

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

For Mi5 Plus speed testing with image extraction:

```bash
poetry run python -m bwpatcher mi5plus firmware.bin mi5plus_flash_image_35.bin sld=35,img
```

Always maintain raw backups of your original firmware before performing any modifications or manual hardware flashing.

## License

Licensed under CC BY-NC-SA 4.0 (NonCommercial, ShareAlike). See [LICENSE](LICENSE) for full terms.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to this project.

## Disclaimer

This tool is provided for educational and research purposes only. The authors accept no liability for any consequences of using this software. See [LEGAL_DISCLAIMER.md](LEGAL_DISCLAIMER.md) for complete terms.
