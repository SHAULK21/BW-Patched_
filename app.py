from bwpatcher.utils import SignatureException, patch_firmware
from bwpatcher.modules import ALL_MODULES
from io import BytesIO
import hashlib
import streamlit as st
from streamlit_scroll_to_top import scroll_to_here


title = "Brightway Firmware Patcher"
st.set_page_config(
    page_title=title,
    page_icon="🛴",
    layout="centered",
    initial_sidebar_state="collapsed"
)

if st.session_state.get("scroll_to_top", False):
    st.session_state.scroll_to_top = False
    scroll_to_here(0, key='top')

st.markdown("""
<style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    .block-container { padding-top: 2rem; padding-bottom: 2rem; max-width: 800px; }
    h1 { text-align: center; margin-bottom: 0.5rem; }
    h2, h3 { margin-top: 2rem; margin-bottom: 1rem; }
</style>
""", unsafe_allow_html=True)

if 'disclaimer_accepted' not in st.session_state:
    st.session_state.disclaimer_accepted = False

if not st.session_state.disclaimer_accepted:
    st.title("⚠️ LEGAL DISCLAIMER - READ CAREFULLY")
    st.error("**You must read and accept this disclaimer before using this tool.**")
    st.markdown("""
    ## Educational and Research Use Only

    **This tool is for EDUCATIONAL and RESEARCH purposes only.**

    Modifying firmware can void warranty, violate local laws, bypass safety features,
    create serious injury risk, and make a device illegal to operate. You assume all risk.

    **No Commercial Use:** This software is CC-BY-NC-SA licensed; commercial use is prohibited.

    See the repository legal disclaimer and principles before use.
    """)
    col1, col2 = st.columns(2)
    with col1:
        if st.button("❌ I Do Not Accept - Exit", use_container_width=True):
            st.error("You must accept the disclaimer to use the tool.")
            st.stop()
    with col2:
        if st.button("✅ I Understand & Accept All Risks", use_container_width=True, type="primary"):
            st.session_state.disclaimer_accepted = True
            st.session_state.scroll_to_top = True
            st.rerun()
    st.stop()

st.title("🛴 Brightway Firmware Patcher")
st.caption("Research tool")

with st.expander("⚖️ View Legal Disclaimer Again"):
    st.markdown("See [LEGAL_DISCLAIMER.md](https://github.com/scooterteam/bw-flasher/blob/main/LEGAL_DISCLAIMER.md) for complete terms.")

st.divider()
st.subheader("📁 Upload Firmware")
uploaded_file = st.file_uploader("Choose your .bin firmware file", type=["bin"])
advanced_mode = st.checkbox("⚡ Advanced: I'm patching a full dump (not DFU firmware)")

st.subheader("🛴 Scooter Model")
scooter_model = st.selectbox("Select your model", ALL_MODULES)

if uploaded_file and scooter_model:
    st.success(f"Ready to configure patches for {scooter_model}")

    # Mi5 Plus preflight uses the actual module and therefore catches stale,
    # wrong-model, wrong-revision and bad-signature cases before patching.
    if scooter_model == "mi5plus":
        try:
            from bwpatcher.modules.mi5plus import Mi5plusPatcher
            probe = Mi5plusPatcher(uploaded_file.getvalue())
            fp = probe.firmware_fingerprint()
            st.markdown("#### 🔍 Mi5 Plus preflight")
            c1, c2 = st.columns(2)
            with c1:
                st.write(f"Size: `{fp['size']}` bytes")
                st.write(f"SHA-256: `{fp['sha256']}`")
            with c2:
                st.write(f"Reference image: `{fp['known_original']}`")
                try:
                    hook = probe.find_speed_hook()
                    st.write(f"Speed hook: `0x{hook:05X}` ✅")
                except Exception as exc:
                    st.write(f"Speed hook: ❌ `{exc}`")
            try:
                crc = probe.verify_checksum()
                st.write(f"Container CRC: `{crc['stored']:04X}` / computed `{crc['computed']:04X}` — `{crc['valid']}`")
            except Exception as exc:
                st.write(f"Container CRC: `{exc}`")
            st.caption("The preflight does not modify the uploaded file.")
        except Exception as exc:
            st.warning(f"Mi5 Plus preflight unavailable: {exc}")

st.divider()
st.subheader("🔧 Configure Patches")
patches = []

if scooter_model not in ["mi5elite"]:
    if st.checkbox('Region Free (RFM)'):
        patches.append("rfm")

if st.checkbox('Speed Limit Sport (SLS)'):
    sls_speed = st.slider("Max Speed (SLS)", 1.0, 35.0, 25.0, 0.1)
    patches.append(f'sls={sls_speed}')

if st.checkbox('Speed Limit Drive (SLD)'):
    sld_speed = st.slider("Max Speed (SLD)", 1.0, 35.0, 15.0, 0.1)
    patches.append(f'sld={sld_speed}')

if scooter_model in ['mi5elite']:
    if st.checkbox('Speed Limit Pedestrian (SLP)'):
        slp_speed = st.slider("Max Speed (SLP)", 1.0, 35.0, 6.0, 0.1)
        patches.append(f'slp={slp_speed}')

if scooter_model in ['mi4', 'ultra4']:
    if st.checkbox('Dashboard Max Speed (DMS)'):
        dms_speed = st.slider("Max Speed (DMS)", 1.0, 29.6, 22.0, 0.1)
        patches.append(f'dms={dms_speed}')

if scooter_model not in ["mi4pro2nd", "mi5pro", "mi5elite"]:
    if st.checkbox('Fake Firmware Version (FDV)'):
        fdv_version = st.text_input("Firmware Version (4 digits)", value="0000", max_chars=4)
        if len(fdv_version) == 4 and fdv_version.isdigit():
            patches.append(f"fdv={fdv_version}")

if scooter_model not in ["mi5elite"]:
    if st.checkbox('Cruise Control Enable (CCE)'):
        patches.append("cce")

if scooter_model not in ["mi4", "mi4lite"]:
    if st.checkbox('Motor Start Speed (MSS)'):
        mss_speed = st.slider("Motor Start Speed (MSS)", 1.0, 9.0, 5.0, 0.1)
        patches.append(f"mss={mss_speed}")

# Mi5 Plus: explicitly choose whether the final artifact should be the raw
# embedded MCU image or the modified OTA container.
extract_image = False
if scooter_model == "mi5plus" and uploaded_file is not None:
    extract_image = st.checkbox(
        "📦 После патча извлечь встроенный MCU image (без OTA-трейлера)",
        value=False,
        help="Удаляет только валидированный OTA trailer. Не создаёт искусственный 64 KiB образ."
    )

st.divider()

if patches:
    st.info(f"{len(patches)} patch(es) selected")
else:
    st.info("No patches selected")

if uploaded_file is not None and patches:
    if not advanced_mode and patches[-1] != "chk":
        patches.append("chk")
    if scooter_model == "mi5plus" and extract_image:
        patches.append("img")
    elif scooter_model == "mi5elite":
        patches.append("img")

    if st.button("Apply Patches", type="primary", use_container_width=True):
        with st.spinner("Applying patches..."):
            input_firmware = uploaded_file.getvalue()
            try:
                patched_firmware = patch_firmware(scooter_model, input_firmware, patches)
                suffix = "raw_mcu_image" if extract_image and scooter_model == "mi5plus" else "ota"
                st.success("Patching complete!")
                st.download_button(
                    label="Download Patched Firmware",
                    data=BytesIO(patched_firmware),
                    file_name=f"patched_{scooter_model}_{suffix}.bin",
                    mime="application/octet-stream",
                    type="primary",
                    use_container_width=True
                )
            except SignatureException as e:
                # Show the exact patch and module error. Do not claim every
                # SignatureException is a firmware mismatch.
                st.error(f"Patching failed: {str(e)}")
                st.warning("Один из выбранных патчей не прошёл проверку. Смотри точное имя patch выше.")
                st.caption(
                    f"Model: {scooter_model} | File size: {len(input_firmware)} bytes | "
                    f"Patches: {', '.join(patches)}"
                )
            except Exception as e:
                st.error(f"Patching failed: {str(e)}")
                st.caption(
                    f"Model: {scooter_model} | File size: {len(input_firmware)} bytes | "
                    f"Patches: {', '.join(patches)}"
                )

elif uploaded_file is None:
    st.warning("Please upload a firmware file")
elif not patches:
    st.warning("Please select at least one patch")

st.divider()
st.caption("For educational and research purposes only • CC-BY-NC-SA 4.0")
