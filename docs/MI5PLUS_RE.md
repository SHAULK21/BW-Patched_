# Xiaomi Scooter 5 Plus — RE status

This document is the evidence baseline for `mi5plus` reverse engineering.
It is based on the raw firmware image used in the current investigation:

- file size: `125371` bytes
- SHA-256: `bdcec9c57c53279a19c28e437003e06e11f441170a349f94f7fdb140edd33cf4`
- architecture: ARM Cortex-M Thumb/Thumb-2
- assumed Flash base: `0x08000000`

## Confidence policy

`CONFIRMED` means the claim is directly supported by bytes/disassembly from the
actual BIN. `STRONG CANDIDATE` means there is useful local evidence but the
semantics are not completely proven. `UNVERIFIED` means it must not be used as
a patch target.

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

The PC-relative literal loaded by the preceding `LDR r1,[PC,...]` resolves to
runtime RAM address `0x20000234` in the investigated image.

This is the only speed byte hook currently treated as `CONFIRMED`.

## Confirmed controller block

The function beginning at file offset `0x3698` / MCU `0x08003698` is real
controller code, but an earlier AI-generated reconstruction contained incorrect
instruction bytes. The following facts are supported by the actual image:

- runtime speed input is read from `0x20000234`;
- at `0x3740..0x3744`, byte `0x200002E5` is compared with `1`;
- the normal path multiplies a working value by `0xAE` (`174`), divides by `10`
  through the existing helper, and stores the result at control-object `+0x18`;
- the control object resolves to RAM `0x20001E40`;
- at `0x376A..0x376E`, the special path constructs `0x1B3` (`435`);
- at `0x378C..0x3796`, `control+0x14` is compared with `control+0x18` and
  clamped downward when the target is higher than the limit.

The semantic meaning of every intermediate field must still be stated with
appropriate confidence; do not copy the obsolete `SDIV at 0x36A2` description.

## Confirmed / refuted mode claims

`0x20001E22` is a real RAM address referenced by the function at `0x0800345C`.
The field `+0x0A` therefore maps to `0x20001E2C` and is written in that function.

However, the actual writes are not literal `1` and `2`; the value depends on
other runtime state. Therefore:

- `0x20001E2C` as a real state field: **CONFIRMED**
- `0x20001E2C = 0/1/2 Eco/Drive/Sport`: **UNVERIFIED**
- `0x0800A412` as its writer: **REFUTED**
- `0x08005834` as a default `1` mode write: **REFUTED**

`0x200002B7` is used as a runtime index/state in the protocol/configuration
logic and is not a proven three-mode selector.

## Refuted region claim

File offsets `0x3440` and `0x3C80` were previously described as seven-entry
regional speed tables. Direct byte inspection shows pointer/literal-pool-like
contents (`0x2000xxxx` values and code/data), so they must **not** be overwritten.
The production `mi5plus` module therefore refuses the old blind region patch.

## What the integrated RE analyzer does

`bwpatcher/re/thumb_re.py` provides:

- raw-image SHA-256 and vector-table validation;
- ARM Thumb/Thumb-2 decoding through the existing Capstone dependency;
- CFG-style recovery starting from Cortex-M vector entries;
- PC-relative literal resolution;
- bounded register-constant data-flow;
- memory reader/writer searches for RAM/Flash targets;
- mode-like `CMP #0/#1/#2` candidate detection;
- exact speed-hook identification;
- JSON-friendly reports.

The analyzer is intentionally analysis-only and never writes firmware bytes.

CLI:

```bash
python tools/analyze_mi5plus.py path/to/mcu_xiaomi.scooter.5plus.bin
python tools/analyze_mi5plus.py path/to/firmware.bin --target 0x20001E2C --json report.json
```

## How to continue Eco/Drive/Sport RE

Start from the verified speed hook and trace the base register backwards:

```text
0x08005C76  LDRB r0,[r7,#9]
        |
        +--> determine how r7 is formed
              |
              +--> identify the structure at r7
                    |
                    +--> identify writers of its +0x09 field
                          |
                          +--> connect the structure to mode/state logic
```

In parallel, inspect the real state field around `0x20001E22` and especially
writers/readers of `0x2000025C` / `0x2000034E`. A mode label is only warranted
when a concrete value can be followed from a mode-selection input to a distinct
control path.

## How to continue current/power RE

Use the same data-flow method. Look for:

- ADC/battery-current conversion and clamp;
- phase current / Iq / current reference limits;
- battery voltage × current or other power calculations;
- temperature-derived current/power derating.

Never infer `0xC8`, `0x12C`, `0x200`, `×100`, etc. as limits merely because
they look plausible. Connect source → scaling → comparison/clamp → actuator.

## Important testing rule

The Python patcher should only patch a signature that is verified against the
actual BIN. For production patching, the exact original bytes and expected
firmware fingerprint must be checked before writing.
