# Xiaomi Scooter 5 Plus — RE status

This document is the evidence baseline for `mi5plus` reverse engineering.
It is based on the raw firmware package used during the investigation:

- file size: `125371` bytes
- SHA-256: `bdcec9c57c53279a19c28e437003e06e11f441170a349f94f7fdb140edd33cf4`
- architecture: ARM Cortex-M Thumb/Thumb-2
- assumed Flash base: `0x08000000`

## Confidence policy

`CONFIRMED` means the claim is directly supported by bytes/disassembly from the actual BIN. `STRONG CANDIDATE` means there is useful local evidence but the semantics are not completely proven. `UNVERIFIED` means it must not be used as a patch target. `REFUTED` means direct byte-level evidence contradicts the claim.

## Confirmed speed hook

At file offset `0x5C74` / MCU address `0x08005C74`:

```text
AB 49 78 7A 08 80
```

The middle instruction is at `0x5C76`:

```text
78 7A  = LDRB r0, [r7, #9]
```

The following instruction is:

```text
08 80  = STRH r0, [r1]
```

The preceding PC-relative literal resolves to runtime RAM `0x20000234` in the investigated image.

This is the only speed byte hook currently treated as `CONFIRMED`.

## Confirmed controller block

The function beginning at file offset `0x3698` / MCU `0x08003698` is real controller code. The current evidence supports:

- runtime speed input is read from `0x20000234`;
- a byte at `0x200002E5` is checked against `1` around `0x3740..0x3744`;
- the configured path performs multiplication by `0xAE` (`174`) and division by `10` through the existing helper;
- the resulting value is stored in control-object `+0x18`;
- the control object resolves to RAM `0x20001E40` in the investigated image;
- the later path constructs `0x1B3` (`435`) around `0x376A..0x376E`;
- at `0x378C..0x3796`, `control+0x14` is compared with `control+0x18` and clamped downward when the target is higher than the limit.

### `0x200002E5` semantic status

The address is **CONFIRMED as a byte read/check in the controller function**. Its higher-level meaning is **UNVERIFIED**.

An earlier interpretation — `0x200002E5 == 1` means "force 435" — is rejected. The patcher does not encode that semantic and does not patch this byte.

## Mi5 Plus container CRC-16

The 5 Plus package contains a verified container integrity field:

- marker: `SZMC-ES-02664-LQ` at file `0x90`;
- size field: `0x8C00` at file `0x86`, big-endian;
- stored CRC: `0xEC8C` at file `0xB0`, big-endian;
- protected data range: `[0x100:0x8D00)`;
- CRC: CRC-16-CCITT, polynomial `0x1021`, init `0x0000`, non-reflected, xorout `0x0000`.

For the pristine reference package the computed CRC equals the stored `0xEC8C`.
Because the speed hook lies inside the protected range, `mi5plus` recalculates this CRC after changing speed.

The generic ES32 checksum routine is intentionally not used for 5 Plus because it expects a different container marker/layout.

## OTA package → embedded MCU image

The reference file is an OTA container with a signed trailer rather than a bare raw image. The trailer begins with a unique binary marker:

```text
MI EF TFOTA
```

The exact marker starts at file offset `0x1E484`. The preceding bytes at `0x1E480..0x1E483` are zero padding. The marker is followed by the model identifier `xiaomi.scooter.5plus` and X.509 certificate material.

For the reference package:

```text
OTA size:             125371 bytes (0x1E9BB)
Image boundary:       0x1E484
Embedded image size:  124036 bytes (0x1E484)
OTA trailer size:     1335 bytes (0x537)
```

The production `mi5plus` `img` operation validates the trailer and existing CRC, then keeps the exact prefix before the trailer. It does not synthesize a new 64 KiB image, and it does not shift any firmware-relative addresses.

```text
OTA package
    ↓
validate MI EF TFOTA + model + certificate
    ↓
verify CRC
    ↓
keep data[:0x1E484]
    ↓
embedded MCU image
```

CLI:

```bash
python -m bwpatcher mi5plus firmware.bin output_image.bin img
```

Patch speed and then extract the image:

```bash
python -m bwpatcher mi5plus firmware.bin output_image_35.bin sld=35,img
```

`img` refuses extraction when the OTA trailer or CRC cannot be validated. When an already-extracted image is supplied, it is accepted only when the confirmed speed hook can still be located.

## Confirmed / refuted mode claims

`0x20001E22` is a real RAM address referenced by code and field `+0x0A` maps to `0x20001E2C`. The field is written, but its value is derived from other runtime state.

Current status:

- `0x20001E22` / field `+0x0A` as a real RAM state field: **CONFIRMED**
- `0x20001E2C = 0/1/2 Eco/Drive/Sport`: **UNVERIFIED**
- `0x0800A412` as its writer: **REFUTED**
- `0x08005834` as a default `1` mode write: **REFUTED**

`0x200002B7` is used as a runtime index/state in protocol/configuration logic and is not a proven three-mode selector.

## Refuted region claim

File offsets `0x3440` and `0x3C80` were previously described as seven-entry regional speed tables. Direct byte inspection shows pointer/literal-pool-like contents (`0x2000xxxx` values and code/data), so they must **not** be overwritten. The production `mi5plus` module refuses the old blind region patch.

## Production patcher behavior

The `mi5plus` module:

1. identifies the speed hook from its instruction shape and requires a unique match;
2. replaces only the 2-byte `LDRB` instruction with Thumb `MOVS r0,#imm8`;
3. recalculates the verified 5 Plus CRC-16 after the patch;
4. can strip the validated OTA trailer with `img` while preserving the complete embedded image prefix;
5. leaves mode selection and region changes untouched until their semantics are independently proven.

All public speed controls currently reach the same verified speed hook. This does not claim that three independent Flash speed bytes have been found.

## How to continue Eco/Drive/Sport RE

Start from the verified speed hook and trace the base register backwards:

```text
0x08005C76  LDRB r0,[r7,#9]
        |
        +--> determine how r7 is formed
              |
              +--> determine whether r7 is a profile pointer or a fixed RAM base
                    |
                    +--> identify writers/readers of the +0x09 source
                          |
                          +--> connect the value to mode/state input
```

Also inspect the real state field around `0x20001E22`, but do not assign Eco/Drive/Sport semantics until a concrete value can be followed from an input packet or state transition into a distinct control path.

## How to continue current/power RE

Use the same data-flow method. Look for:

- ADC/battery-current conversion and clamp;
- phase current / Iq / current reference limits;
- battery voltage × current or other power calculations;
- temperature-derived current/power derating.

Never infer `0xC8`, `0x12C`, `0x200`, `×100`, etc. as limits merely because they look plausible. Connect source → scaling → comparison/clamp → actuator.

## Important testing rule

The Python patcher should only patch a signature that is verified against the actual BIN. For production patching, the exact original bytes and expected firmware fingerprint should be checked before writing.
