from bwpatcher.utils import SignatureException, patch_firmware
from bwpatcher.modules import ALL_MODULES
from io import BytesIO
import streamlit as st
from streamlit_scroll_to_top import scroll_to_here


title = "Brightway Firmware Patcher"
st.set_page_config(page_title=title, page_icon="🛴", layout="centered", initial_sidebar_state="collapsed")

if st.session_state.get("scroll_to_top", False):
    st.session_state.scroll_to_top = False
    scroll_to_here(0, key="top")

st.markdown("""
<style>
#MainMenu {visibility:hidden;} footer {visibility:hidden;}
.block-container {padding-top:2rem; padding-bottom:2rem; max-width:800px;}
h1 {text-align:center; margin-bottom:.5rem;}
h2,h3 {margin-top:2rem; margin-bottom:1rem;}
</style>
""", unsafe_allow_html=True)

if not st.session_state.get("disclaimer_accepted", False):
    st.title("⚠️ LEGAL DISCLAIMER - READ CAREFULLY")
    st.error("**You must read and accept this disclaimer before using the tool.**")
    st.markdown("""
    ## Educational and Research Use Only
    Firmware modification can void warranty, violate local laws, bypass safety features,
    create serious injury risk, and make a device illegal to operate. You assume all risk.

    **No Commercial Use:** CC-BY-NC-SA; commercial use is prohibited.
    """)
    c1, c2 = st.columns(2)
    with c1:
        if st.button("❌ I Do Not Accept - Exit", use_container_width=True):
            st.error("You must accept the disclaimer to use the tool.")
            st.stop()
    with c2:
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

preflight = None
if uploaded_file is not None and scooter_model == "mi5plus":
    try:
        from bwpatcher.modules.mi5plus import Mi5plusPatcher
        preflight = Mi5plusPatcher(uploaded_file.getvalue())
        fp = preflight.firmware_fingerprint()
        st.success(f"Ready to configure patches for {scooter_model}")
        st.markdown("#### 🔍 Mi 5 Plus preflight")
        c1, c2 = st.columns(2)
        with c1:
            st.write(f"Size: `{fp['size']}` bytes")
            st.write(f"SHA-256: `{fp['sha256']}`")
        with c2:
            st.write(f"Reference image: `{fp['known_original']}`")
            try:
                hook = preflight.find_speed_hook()
                st.write(f"Speed hook: `0x{hook:05X}` ✅")
            except Exception as exc:
                st.write(f"Speed hook: ❌ `{exc}`")
        try:
            crc = preflight.verify_checksum()
            st.write(f"CRC: `{crc['stored']:04X}` / `{crc['computed']:04X}` — valid=`{crc['valid']}`")
        except Exception as exc:
            st.write(f"CRC: `{exc}`")
    except Exception as exc:
        st.warning(f"Mi5 Plus preflight unavailable: {exc}")
elif uploaded_file is not None:
    st.success(f"Ready to configure patches for {scooter_model}")

st.divider()
st.subheader("🔧 Configure Patches")
patches = []
extract_image = False

if scooter_model == "mi5plus":
    # Mi5 Plus currently has one verified common active-profile speed hook.
    # Do not expose other model-general patches that still rely on generic
    # ES32 signatures and can produce misleading "Pattern not found" errors.
    use_speed = st.checkbox("Speed Limit — verified Mi 5 Plus active-profile hook", value=True)
    speed = st.slider("Target speed parameter", 1.0, 45.0, 35.0, 1.0)
    if use_speed:
        patches.append(f"sld={speed}")

    extract_image = st.checkbox(
        "📦 Output raw embedded MCU image (remove validated OTA trailer)",
        value=False,
        help="For the reference OTA this strips only the validated MI EF TFOTA trailer; it does not synthesize a 64 KiB image."
    )
else:
    if scooter_model not in ["mi5elite"] and st.checkbox("Region Free (RFM)"):
        patches.append("rfm")

    if st.checkbox("Speed Limit Sport (SLS)"):
        sls_speed = st.slider("Max Speed (SLS)", 1.0, 35.0, 25.0, 0.1)
        patches.append(f"sls={sls_speed}")

    if st.checkbox("Speed Limit Drive (SLD)"):
        sld_speed = st.slider("Max Speed (SLD)", 1.0, 35.0, 15.0, 0.1)
        patches.append(f"sld={sld_speed}")

    if scooter_model == "mi5elite" and st.checkbox("Speed Limit Pedestrian (SLP)"):
        slp_speed = st.slider("Max Speed (SLP)", 1.0, 35.0, 6.0, 0.1)
        patches.append(f"slp={slp_speed}")

    if scooter_model in ["mi4", "ultra4"] and st.checkbox("Dashboard Max Speed (DMS)"):
        dms_speed = st.slider("Max Speed (DMS)", 1.0, 29.6, 22.0, 0.1)
        patches.append(f"dms={dms_speed}")

    if scooter_model not in ["mi4pro2nd", "mi5pro", "mi5elite"] and st.checkbox("Fake Firmware Version (FDV)"):
        fdv_version = st.text_input("Firmware Version (4 digits)", value="0000", max_chars=4)
        if len(fdv_version) == 4 and fdv_version.isdigit():
            patches.append(f"fdv={fdv_version}")

    if scooter_model not in ["mi5elite"] and st.checkbox("Cruise Control Enable (CCE)"):
        patches.append("cce")

    if scooter_model not in ["mi4", "mi4lite"] and st.checkbox("Motor Start Speed (MSS)"):
        mss_speed = st.slider("Motor Start Speed (MSS)", 1.0, 9.0, 5.0, 0.1)
        patches.append(f"mss={mss_speed}")

st.divider()

if patches:
    st.info(f"{len(patches)} patch(es) selected")
else:
    st.info("No patches selected")

if uploaded_file is not None and patches:
    if not advanced_mode and "chk" not in patches:
        patches.append("chk")
    if scooter_model == "mi5plus" and extract_image:
        patches.append("img")
    elif scooter_model == "mi5elite":
        patches.append("img")

    st.caption(f"Patch chain: {', '.join(patches)}")

    if st.button("Apply Patches", type="primary", use_container_width=True):
        with st.spinner("Applying patches..."):
            input_firmware = uploaded_file.getvalue()
            try:
                patched_firmware = patch_firmware(scooter_model, input_firmware, patches)
                suffix = "raw_mcu_image" if scooter_model == "mi5plus" and extract_image else "ota"
                st.success("Patching complete!")
                st.download_button(
                    label="Download Patched Firmware",
                    data=BytesIO(patched_firmware),
                    file_name=f"patched_{scooter_model}_{suffix}.bin",
                    mime="application/octet-stream",
                    type="primary",
                    use_container_width=True,
                )
            except SignatureException as exc:
                st.error(f"Patching failed: {exc}")
                st.caption(
                    f"Model: {scooter_model} | File size: {len(input_firmware)} bytes | "
                    f"Patches: {', '.join(patches)}"
                )
            except Exception as exc:
                st.error(f"Patching failed: {exc}")
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
