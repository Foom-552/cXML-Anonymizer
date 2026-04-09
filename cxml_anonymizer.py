import io
import zipfile
from datetime import datetime
from pathlib import Path

import streamlit as st

# Use defusedxml to prevent XML bomb / entity expansion attacks (e.g. Billion Laughs).
# pip install defusedxml lxml
try:
    import defusedxml.ElementTree as safe_ET
except ImportError:
    st.error("Missing dependency: `defusedxml`. Run `pip install defusedxml` and restart.")
    st.stop()

try:
    from lxml import etree as lxml_ET
except ImportError:
    st.error("Missing dependency: `lxml`. Run `pip install lxml` and restart.")
    st.stop()

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

# Generic / universal anonymization rules.
# Keys match either XML element tag names or attribute names.
GENERIC_ANONYMIZATION_MAP: dict[str, str] = {
    "Name": "Anonymized Name",
    "Email": "test.user@anonymized.com",
    "Street": "123 Anonymized St",
    "Description": "Anonymized Item Description",
    "Comments": "Anonymized comment.",
    "SupplierPartID": "ANONYMIZED_PART_ID",
    "BuyerPartID": "ANONYMIZED_PART_ID",
    "agreementID": "ANONYMIZED_AGREEMENT_ID",
    "addressID": "ANONYMIZED_ADDRESS_ID",
    "agreementItemNumber": "0",
    "documentID": "ANONYMIZED_DOC_ID",
}

# Regional profiles supply locale-specific anonymized replacement values.
# Region is detected automatically from the document — never set by the user.
# Keys here take precedence over GENERIC_ANONYMIZATION_MAP when both define the
# same key (e.g. "currency"). This precedence is intentional and documented here.
REGIONAL_PROFILES: dict[str, dict[str, str]] = {
    "AU": {
        "display_name": "Australia (AU)",
        "City": "Anonymized City",
        "State": "WA",
        "PostalCode": "6000",
        "Country": "Australia",
        "isoCountryCode": "AU",
        "Money": "1.00",
        "currency": "AUD",
        "Number": "0891234567",
    },
    "NAMAR": {
        "display_name": "North America (NAMAR)",
        "City": "Anonymized City",
        "State": "CA",
        "PostalCode": "90210",
        "Country": "United States",
        "isoCountryCode": "US",
        "Money": "1.00",
        "currency": "USD",
        "Number": "555-555-5555",
    },
    "EMEA": {
        "display_name": "Europe, Middle East & Africa (EMEA)",
        "City": "Anonymized City",
        "State": "BE",
        "PostalCode": "10115",
        "Country": "Germany",
        "isoCountryCode": "DE",
        "Money": "1.00",
        "currency": "EUR",
        "Number": "03012345678",
    },
    "Japan": {
        "display_name": "Japan (JP)",
        "City": "Chiyoda",
        "State": "Tokyo",
        "PostalCode": "100-0001",
        "Country": "Japan",
        "isoCountryCode": "JP",
        "Money": "1.00",
        "currency": "JPY",
        "Number": "0312345678",
    },
}

# ISO 3166-1 alpha-2 country codes -> region key.
ISO_COUNTRY_TO_REGION: dict[str, str] = {
    # Australia / Pacific
    "AU": "AU", "NZ": "AU",
    # North America
    "US": "NAMAR", "CA": "NAMAR", "MX": "NAMAR",
    # Japan
    "JP": "Japan",
    # EMEA - Europe
    "GB": "EMEA", "DE": "EMEA", "FR": "EMEA", "IT": "EMEA", "ES": "EMEA",
    "NL": "EMEA", "BE": "EMEA", "CH": "EMEA", "AT": "EMEA", "SE": "EMEA",
    "NO": "EMEA", "DK": "EMEA", "FI": "EMEA", "IE": "EMEA", "PT": "EMEA",
    "PL": "EMEA", "CZ": "EMEA", "HU": "EMEA", "RO": "EMEA", "GR": "EMEA",
    "SK": "EMEA", "HR": "EMEA", "BG": "EMEA", "RS": "EMEA", "SI": "EMEA",
    "LU": "EMEA", "IS": "EMEA", "LT": "EMEA", "LV": "EMEA", "EE": "EMEA",
    "CY": "EMEA", "MT": "EMEA",
    # EMEA - Middle East
    "AE": "EMEA", "SA": "EMEA", "QA": "EMEA", "KW": "EMEA", "BH": "EMEA",
    "OM": "EMEA", "JO": "EMEA", "LB": "EMEA", "IQ": "EMEA", "IL": "EMEA",
    "TR": "EMEA", "IR": "EMEA", "PK": "EMEA",
    # EMEA - Africa
    "ZA": "EMEA", "NG": "EMEA", "EG": "EMEA", "KE": "EMEA", "GH": "EMEA",
    "TZ": "EMEA", "MA": "EMEA", "DZ": "EMEA", "TN": "EMEA",
}

# Currency codes -> region key (fallback when no country code is present).
CURRENCY_TO_REGION: dict[str, str] = {
    "AUD": "AU", "NZD": "AU",
    "USD": "NAMAR", "CAD": "NAMAR", "MXN": "NAMAR",
    "JPY": "Japan",
    "EUR": "EMEA", "GBP": "EMEA", "CHF": "EMEA", "SEK": "EMEA",
    "NOK": "EMEA", "DKK": "EMEA", "PLN": "EMEA", "CZK": "EMEA",
    "HUF": "EMEA", "RON": "EMEA", "ZAR": "EMEA", "AED": "EMEA",
    "SAR": "EMEA", "TRY": "EMEA", "ILS": "EMEA", "QAR": "EMEA",
}

DEFAULT_REGION = "AU"

# Attribute names that are always considered sensitive and scrubbed regardless
# of whether they appear in the anonymization map.
SENSITIVE_ATTR_NAMES: set[str] = {"name", "email", "phone", "contact", "firstName", "lastName"}

# Extrinsic name="" values whose text content should be left completely unchanged.
# These are system/classification codes where the real value is required for
# Test Central setup and carries no personally identifiable information.
PRESERVE_EXTRINSIC_NAMES: set[str] = {
    "extLineNumber",               # Line sequence number — structural, not sensitive
    "materialStorageLocation",     # Storage location code
    "warehouseStorageLocationNo",  # Warehouse location number
    "incoTerm",                    # Incoterm code (e.g. CFR, EXW)
    "incoTermDesc",                # Incoterm description
    "incoTermLocation",            # Incoterm location
    "CompanyCode",                 # SAP company code
    "PurchaseGroup",               # SAP purchasing group
    "PurchaseOrganization",        # SAP purchasing organisation
    "Ariba.invoicingAllowed",      # Boolean flag (Yes/No)
    "AribaNetwork.PaymentTermsExplanation",  # Standard payment terms text
    "transactionCategoryOrType",   # Document category (e.g. Goods PO)
}

# Maps the Extrinsic name="" attribute to a meaningful anonymized placeholder.
# The name attribute itself is always preserved as-is.
# Fields listed in PRESERVE_EXTRINSIC_NAMES are skipped entirely before this map is checked.
# Any Extrinsic whose name is not in either set falls back to "ANONYMIZED_EXTRINSIC_VALUE".
EXTRINSIC_ANONYMIZATION_MAP: dict[str, str] = {
    # Tax & registration identifiers
    "supplierVatID": "Supplier ABN",
    "buyerVatID": "Buyer ABN",
    "vatID": "ABN",
    "taxID": "TAX-ID-000000000",
    "taxExemptionNumber": "TAX-EXEMPT-000000",
    "abn": "000000000",
    "gst": "GST-000000000",
    "businessIdentNo": "BUSINESS-ID-00000000000",

    # Supplier / buyer identifiers
    "supplierID": "SUPPLIER-ID-00000",
    "buyerID": "BUYER-ID-00000",
    "vendorID": "VENDOR-ID-00000",
    "VendorIdNumber": "VENDOR-ID-0000",
    "vendorAbbreviationCode": "Anonymized Vendor",
    "partyAdditionalID": "PARTY-ID-00000000",
    "customerId": "CUSTOMER-ID-00000",
    "customerNumber": "CUSTOMER-00000",
    "supplierNumber": "SUPPLIER-00000",
    "accountNumber": "ACCOUNT-00000",
    "erp_supplier_id": "ERP-SUPPLIER-00000",
    "erp_vendor_id": "ERP-VENDOR-00000",
    "manufacturerNo": "MANUFACTURER-00000",
    "receiverID": "RECEIVER-ID-00000",

    # Contact / user details
    "userIdentification": "Anonymized User",
    "mailbox": "anonymized.user@anonymized.com",
    "supplementNo": "ANONYMIZED-PHONE",             # Phone number stored in supplementNo
    "Requester": "Anonymized Requester",
    "contactName": "Anonymized Contact",
    "buyerContact": "Anonymized Buyer Contact",
    "supplierContact": "Anonymized Supplier Contact",
    "requestorName": "Anonymized Requestor",
    "approverName": "Anonymized Approver",
    "userID": "USER-ID-00000",
    "userId": "USER-ID-00000",
    "loginID": "LOGIN-ID-00000",
    "username": "anonymized.user",

    # Procurement / document references
    "requestForQuotationRef": "RFQ-0000000000-00000",
    "relatedContractLineItemNo": "CONTRACT-LINE-0000000000-00000",
    "purchaseRequisitionNo": "PR-0000000000-00000",
    "customerReferenceNo": "CUSTOMER-REF-00000",
    "transactionReferenceNo": "TRANSACTION-REF-00000",
    "contractID": "CONTRACT-ID-00000",
    "agreementID": "AGREEMENT-ID-00000",
    "masterAgreementID": "MASTER-AGREEMENT-00000",
    "purchaseAgreementID": "PA-ID-00000",
    "blanketOrderID": "BO-ID-00000",
    "quoteID": "QUOTE-ID-00000",
    "orderID": "ORDER-ID-00000",
    "requisitionID": "REQ-ID-00000",
    "invoiceID": "INVOICE-ID-00000",
    "deliveryNoteID": "DN-ID-00000",
    "shipmentID": "SHIPMENT-ID-00000",
    "trackingNumber": "TRACKING-000000000",

    # Financial
    "Ariba.availableAmount": "0.00",

    # Work order / operational detail
    "WorkOrderDetail": "Anonymized Work Order Detail",

    # Shipment / destination
    "shipmentDestinationCode": "Anonymized Shipment Destination",

    # Legal / terms text
    "term": "Anonymized Terms and Conditions.",
    "SpecialText": "Anonymized Special Text",

    # Cost centre / GL / org structure
    "costCenter": "COST-CENTER-00000",
    "costCentre": "COST-CENTER-00000",
    "glAccount": "GL-ACCOUNT-00000",
    "glCode": "GL-CODE-00000",
    "wbsElement": "WBS-ELEMENT-00000",
    "profitCenter": "PROFIT-CENTER-00000",
    "companyCode": "COMPANY-CODE-0000",
    "businessUnit": "BUSINESS-UNIT-00000",
    "department": "DEPARTMENT-00000",
    "plant": "PLANT-00000",
    "storageLocation": "STORAGE-LOC-00000",

    # Network / system identifiers
    "networkID": "NETWORK-ID-00000",
    "buyerNetworkID": "BUYER-NETWORK-ID-00000",
    "supplierNetworkID": "SUPPLIER-NETWORK-ID-00000",
    "erpSystemID": "ERP-SYSTEM-ID-00000",
    "systemID": "SYSTEM-ID-00000",
    "instanceID": "INSTANCE-ID-00000",

    # Free-text / comments
    "note": "Anonymized note.",
    "comment": "Anonymized comment.",
    "description": "Anonymized description.",
    "internalNote": "Anonymized internal note.",
}

CXML_DOCTYPE = '<!DOCTYPE cXML SYSTEM "http://xml.cxml.org/schemas/cXML/1.2.069/cXML.dtd">'


# ---------------------------------------------------------------------------
# REGION DETECTION
# ---------------------------------------------------------------------------

def detect_region(root: lxml_ET._Element) -> tuple[str, str]:
    """Automatically detect the region from signals within the parsed cXML tree.

    Detection priority (first match wins):
      1. ``isoCountryCode`` attribute on any ``<Country>`` element.
      2. ``currency`` attribute on any ``<Money>`` element.
      3. Text content of ``<Country>`` elements matched case-insensitively.
      4. Falls back to DEFAULT_REGION ("AU") if nothing is found.

    Returns:
        (region_code, detection_method_description)
    """
    # 1. isoCountryCode attribute
    for el in root.iter():
        if lxml_ET.QName(el.tag).localname == "Country":
            code = el.get("isoCountryCode", "").upper()
            if code in ISO_COUNTRY_TO_REGION:
                region = ISO_COUNTRY_TO_REGION[code]
                return region, f"isoCountryCode='{code}'"

    # 2. currency attribute on <Money>
    for el in root.iter():
        if lxml_ET.QName(el.tag).localname == "Money":
            currency = el.get("currency", "").upper()
            if currency in CURRENCY_TO_REGION:
                region = CURRENCY_TO_REGION[currency]
                return region, f"currency='{currency}'"

    # 3. Country text content
    COUNTRY_NAME_MAP: dict[str, str] = {
        "australia": "AU", "new zealand": "AU",
        "united states": "NAMAR", "usa": "NAMAR", "canada": "NAMAR", "mexico": "NAMAR",
        "japan": "Japan",
        "germany": "EMEA", "france": "EMEA", "united kingdom": "EMEA",
        "uk": "EMEA", "england": "EMEA", "netherlands": "EMEA",
        "spain": "EMEA", "italy": "EMEA", "sweden": "EMEA", "norway": "EMEA",
        "denmark": "EMEA", "finland": "EMEA", "switzerland": "EMEA",
        "austria": "EMEA", "belgium": "EMEA", "ireland": "EMEA",
        "south africa": "EMEA", "united arab emirates": "EMEA", "uae": "EMEA",
        "saudi arabia": "EMEA",
    }
    for el in root.iter():
        if lxml_ET.QName(el.tag).localname == "Country" and el.text:
            name = el.text.strip().lower()
            if name in COUNTRY_NAME_MAP:
                region = COUNTRY_NAME_MAP[name]
                return region, f"country name='{el.text.strip()}'"

    # 4. Default fallback
    return DEFAULT_REGION, "fallback default"


# ---------------------------------------------------------------------------
# VALIDATION
# ---------------------------------------------------------------------------

def validate_cxml_file(xml_content: str) -> tuple[bool, str, str | None]:
    """Validate an uploaded file as a well-formed, structurally correct cXML document.

    Uses defusedxml as a security gate, then lxml for structural inspection.

    Returns:
        (is_valid, message, document_type)
        document_type is None when is_valid is False.
    """
    # Security gate — raises on malicious XML before anything else
    try:
        safe_ET.fromstring(xml_content.encode())
    except Exception as e:
        return False, f"XML security check failed: {e}", None

    # Structural validation via lxml
    try:
        root = lxml_ET.fromstring(xml_content.encode())
    except lxml_ET.XMLSyntaxError as e:
        return False, f"XML parsing error: {e}", None

    root_local = lxml_ET.QName(root.tag).localname
    if root_local != "cXML":
        return False, f"Invalid root element <{root_local}>. Expected <cXML>.", None

    if "payloadID" not in root.attrib:
        return False, "Missing required 'payloadID' attribute on <cXML>.", None

    if root.find("Header") is None:
        return False, "Missing required <Header> element.", None

    # Detect document type from request body
    document_type = "Unknown"
    request = root.find("Request")
    response = root.find("Response")

    if request is not None:
        if request.find(".//OrderRequest") is not None:
            document_type = "OrderRequest"
        elif request.find(".//ConfirmationRequest") is not None:
            document_type = "OrderConfirmation"
        elif request.find(".//ShipNoticeRequest") is not None:
            document_type = "ShipNotice"
        elif request.find(".//InvoiceDetailRequest") is not None:
            document_type = "Invoice"
        else:
            document_type = "Request (Other)"
    elif response is not None:
        document_type = "Response"

    return True, "Valid cXML document.", document_type


# ---------------------------------------------------------------------------
# ANONYMIZATION  (unchanged from Script 2)
# ---------------------------------------------------------------------------

def apply_header_template(root: lxml_ET._Element) -> None:
    """Overwrite cXML envelope attributes and the Header / OrderRequestHeader
    with sanitised placeholder values."""
    root.set("payloadID", "#PAYLOADID#")
    root.set("timestamp", "2026-01-01T14:53:00-07:00")
    root.set("version", "1.2.069")
    root.set("{http://www.w3.org/XML/1998/namespace}lang", "en-US")

    header = root.find("Header")
    if header is not None:
        _replace_credential(header.find("From"), "#SENDERID#", "NetworkId")
        _replace_credential(header.find("To"), "#RECEIVERID#", "NetworkId")
        _replace_credential(header.find("Sender"), "#PROVIDERID#", "NetworkID")

        sender_tag = header.find("Sender")
        if sender_tag is not None:
            user_agent = sender_tag.find("UserAgent")
            if user_agent is not None:
                user_agent.text = "Ariba SN"

    request_tag = root.find("Request")
    if request_tag is not None:
        request_tag.set("deploymentMode", "test")
        orh = request_tag.find(".//OrderRequestHeader")
        if orh is not None:
            orh.set("orderDate", "#DATETIME#")
            orh.set("orderID", "#DOCUMENTID#")
            orh.set("orderType", "regular")
            orh.set("orderVersion", "1")
            orh.set("type", "new")


def _replace_credential(
    parent: lxml_ET._Element | None, identity: str, domain: str
) -> None:
    """Remove all Credential / Correspondent children from *parent* and insert
    a single sanitised Credential element."""
    if parent is None:
        return
    for child in list(parent):
        if child.tag in ("Credential", "Correspondent"):
            parent.remove(child)
    cred = lxml_ET.SubElement(parent, "Credential")
    cred.set("domain", domain)
    lxml_ET.SubElement(cred, "Identity").text = identity


def anonymize_elements(element: lxml_ET._Element, profile: dict[str, str]) -> list[str]:
    """Recursively traverse *element* and apply anonymization rules from *profile*.

    Returns a list of human-readable strings describing every substitution made,
    suitable for display in the processing summary.
    """
    log: list[str] = []

    for child in element:
        local_tag = lxml_ET.QName(child.tag).localname  # strip namespace if present

        # --- Element text substitution ---
        if local_tag in profile:
            old = child.text
            child.text = profile[local_tag]
            if old != child.text:
                log.append(f"<{local_tag}> text → `{profile[local_tag]}`")

        # Special-case: Money currency attribute
        if local_tag == "Money" and "currency" in profile:
            child.set("currency", profile["currency"])
            log.append(f"<Money currency> → `{profile['currency']}`")

        # Special-case: Country isoCountryCode attribute
        if local_tag == "Country" and "isoCountryCode" in profile:
            child.set("isoCountryCode", profile["isoCountryCode"])
            log.append(f"<Country isoCountryCode> → `{profile['isoCountryCode']}`")

        # Extrinsic: check preserve list first, then look up a meaningful anonymized
        # value by name, falling back to the generic placeholder for unknowns.
        if local_tag == "Extrinsic":
            extrinsic_name = child.get("name", "")
            if extrinsic_name in PRESERVE_EXTRINSIC_NAMES:
                # Value must not be changed — skip entirely and log the decision
                log.append(f"<Extrinsic name=\"{extrinsic_name}\"> → (preserved)")
            else:
                if extrinsic_name in EXTRINSIC_ANONYMIZATION_MAP:
                    anonymized_value = EXTRINSIC_ANONYMIZATION_MAP[extrinsic_name]
                else:
                    anonymized_value = "ANONYMIZED_EXTRINSIC_VALUE"
                old_text = child.text
                child.text = anonymized_value
                if old_text != anonymized_value:
                    label = f'name="{extrinsic_name}"' if extrinsic_name else "(no name)"
                    log.append(f"<Extrinsic {label}> → `{anonymized_value}`")

        # IdReference identifiers are always scrubbed
        if local_tag == "IdReference" and "identifier" in child.attrib:
            child.set("identifier", "ANONYMIZED_IDENTIFIER")
            log.append("<IdReference identifier> → `ANONYMIZED_IDENTIFIER`")

        # --- Attribute substitution ---
        for attr_name in list(child.attrib):
            local_attr = lxml_ET.QName(attr_name).localname
            # Never overwrite the Extrinsic name= attribute — it is used as the
            # lookup key above and must be preserved in the output.
            if local_tag == "Extrinsic" and local_attr == "name":
                continue
            if local_attr in profile:
                child.set(attr_name, profile[local_attr])
                log.append(f"<{local_tag} {local_attr}> → `{profile[local_attr]}`")
            elif local_attr.lower() in SENSITIVE_ATTR_NAMES:
                child.set(attr_name, "ANONYMIZED")
                log.append(f"<{local_tag} {local_attr}> (sensitive attr) → `ANONYMIZED`")

        log.extend(anonymize_elements(child, profile))

    return log


def _insert_doctype(xml_string: str) -> str:
    """Insert the cXML DOCTYPE declaration immediately after the XML declaration.
    Handles both Unix (LF) and Windows (CRLF) line endings robustly."""
    try:
        end = xml_string.index("?>") + 2
    except ValueError:
        return CXML_DOCTYPE + "\n" + xml_string
    return xml_string[:end] + "\n" + CXML_DOCTYPE + xml_string[end:]


def process_cxml_content(
    xml_content: str,
) -> tuple[str, list[str], str, str]:
    """Parse, anonymize and serialise a cXML document.

    Region is detected automatically from signals within the document.
    Validation is assumed to have already passed (via validate_cxml_file).

    Returns:
        (anonymized_xml_string, substitution_log, region_code, detection_method)
    """
    # Security gate (defusedxml) — result discarded; lxml handles processing
    safe_ET.fromstring(xml_content.encode())

    root: lxml_ET._Element = lxml_ET.fromstring(xml_content.encode())

    # Auto-detect region before any modifications are made to the tree
    region_code, detection_method = detect_region(root)

    # Build merged profile — regional values take precedence
    active_profile: dict[str, str] = {**GENERIC_ANONYMIZATION_MAP, **REGIONAL_PROFILES[region_code]}
    active_profile.pop("display_name", None)

    apply_header_template(root)
    log = anonymize_elements(root, active_profile)

    output_bytes: bytes = lxml_ET.tostring(
        root,
        pretty_print=True,
        xml_declaration=True,
        encoding="utf-8",
    )
    output_string = _insert_doctype(output_bytes.decode("utf-8"))

    return output_string, log, region_code, detection_method


def create_zip_file(files_dict: dict[str, str]) -> io.BytesIO:
    """Bundle *files_dict* {filename: content} into an in-memory ZIP."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, content in files_dict.items():
            zf.writestr(filename, content)
    zip_buffer.seek(0)
    return zip_buffer


# ---------------------------------------------------------------------------
# HELPER: render XML in a scrollable, height-constrained container
# ---------------------------------------------------------------------------

def _render_scrollable_xml(xml_text: str, height_px: int = 400) -> None:
    """Display XML content inside a scrollable <div> with a fixed max height.

    Uses an HTML <pre><code> block styled to constrain height and scroll
    independently, so large documents never blow up the page layout.
    """
    import html as _html

    escaped = _html.escape(xml_text)
    st.markdown(
        f"""
        <div style="
            max-height: {height_px}px;
            overflow: auto;
            border: 1px solid #444;
            border-radius: 6px;
            background-color: #0e1117;
            padding: 0.75rem;
            font-size: 0.82rem;
            line-height: 1.4;
        ">
            <pre style="margin:0; white-space:pre; color:#fafafa;"><code>{escaped}</code></pre>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# STREAMLIT UI
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="cXML Anonymizer Tool",
    page_icon="🔒",
    layout="wide",
)

# ---- Inject global CSS to constrain validation expander and preview heights ----
st.markdown(
    """
    <style>
    /* Make validation-error expander content scrollable */
    div[data-testid="stExpander"] details div[data-testid="stMarkdownContainer"] {
        max-height: 300px;
        overflow-y: auto;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Session state for the clear-all button
if "clear_trigger" not in st.session_state:
    st.session_state.clear_trigger = False

st.title("🔒 cXML Anonymizer Tool")
st.markdown(
    "Securely anonymize cXML transactional documents for Test Central setup. "
    "Accepts **.xml** and **.txt** files."
)
st.divider()

# --- Sidebar ---
with st.sidebar:
    st.header("📖 Instructions")
    st.markdown(
        """
        1. **Upload** one or more cXML files using the file uploader.
        2. Accepted formats: **.xml** and **.txt** containing cXML content.
        3. Click **Anonymize All Documents**.
        4. **Download** individual files or all as a ZIP.
        5. Expand the **Processing Summary** to confirm what was anonymized.
        """
    )
    st.divider()

    st.header("🌍 Auto Region Detection")
    st.markdown(
        """
        The region is detected automatically from each document using
        the following signals (in priority order):

        1. `isoCountryCode` attribute on `<Country>` elements
        2. `currency` attribute on `<Money>` elements
        3. `<Country>` text content

        Detected region determines which anonymized locale values
        (postal code, currency, phone format, etc.) are applied.
        Falls back to **Australia (AU)** if no signal is found.
        """
    )
    st.divider()

    st.header("🔄 Reset")
    if st.button("🗑️ Clear All Files", use_container_width=True):
        st.session_state.clear_trigger = True
        st.rerun()

    st.divider()
    st.info(
        "🔐 **Privacy Notice**\n\n"
        "Uploaded files are processed entirely in-memory within your "
        "session and are never stored, logged, or transmitted to any "
        "third party. No data is retained after your session ends."
    )

# --- File uploader ---
# Key rotates on clear so Streamlit resets the widget state
uploader_key = f"file_uploader_{st.session_state.clear_trigger}"

uploaded_files = st.file_uploader(
    "Upload your cXML files",
    type=["xml", "txt"],
    accept_multiple_files=True,
    help="Select one or more cXML documents to anonymize. Accepts .xml and .txt files containing cXML content.",
    key=uploader_key,
)

# Reset clear trigger after rerun has taken effect
if st.session_state.clear_trigger:
    st.session_state.clear_trigger = False

if not uploaded_files:
    st.info("👆 Please upload one or more cXML files to get started. Accepted formats: .xml and .txt")
    st.stop()

# --- Batch limits ---
MAX_FILES = 50
MAX_FILE_SIZE_MB = 10

oversized = [f.name for f in uploaded_files if len(f.getvalue()) > MAX_FILE_SIZE_MB * 1024 * 1024]
if len(uploaded_files) > MAX_FILES:
    st.error(f"❌ Maximum {MAX_FILES} files allowed per batch. You uploaded {len(uploaded_files)}.")
    st.stop()
if oversized:
    st.error(f"❌ The following file(s) exceed the {MAX_FILE_SIZE_MB} MB size limit and cannot be processed: {', '.join(oversized)}")
    st.stop()

# --- Per-file configuration ---
st.divider()
st.subheader(f"📁 {len(uploaded_files)} File(s) Uploaded")

file_configs: list[dict] = []
validation_errors: list[str] = []

for i, uploaded_file in enumerate(uploaded_files):
    file_content = uploaded_file.getvalue().decode("utf-8")
    is_valid, validation_message, doc_type = validate_cxml_file(file_content)

    # Pre-detect region for display (only for valid files)
    detected_region_label = ""
    detected_by = ""
    if is_valid:
        try:
            root_preview = lxml_ET.fromstring(file_content.encode())
            detected_code, detected_by = detect_region(root_preview)
            detected_region_label = REGIONAL_PROFILES[detected_code]["display_name"]
        except Exception:
            detected_region_label = REGIONAL_PROFILES[DEFAULT_REGION]["display_name"]
            detected_by = "fallback default"

    with st.container():
        # ---- Row 1: file name | region | doc type / status ----
        col1, col2, col3 = st.columns([2, 2, 1])

        with col1:
            file_size = len(uploaded_file.getvalue()) / 1024
            st.markdown(
                f"**📄 {uploaded_file.name}**  \n"
                f"<span style='color:gray; font-size:0.85rem;'>"
                f"Size: {file_size:.1f} KB</span>",
                unsafe_allow_html=True,
            )

        with col2:
            if is_valid:
                st.markdown(
                    f"🌍 **{detected_region_label}**  \n"
                    f"<span style='color:gray; font-size:0.85rem;'>"
                    f"Detected via: {detected_by}</span>",
                    unsafe_allow_html=True,
                )
            else:
                st.empty()

        with col3:
            if is_valid:
                st.markdown(
                    f"<div style='"
                    f"background-color: #0e4429;"
                    f"border: 1px solid #238636;"
                    f"border-radius: 6px;"
                    f"padding: 0.35rem 0.6rem;"
                    f"text-align: center;"
                    f"font-size: 0.85rem;"
                    f"color: #3fb950;"
                    f"line-height: 1.3;"
                    f"margin-top: 0.25rem;"
                    f"'>✅ {doc_type}</div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"<div style='"
                    f"background-color: #4a1a1a;"
                    f"border: 1px solid #d73a49;"
                    f"border-radius: 6px;"
                    f"padding: 0.35rem 0.6rem;"
                    f"text-align: center;"
                    f"font-size: 0.85rem;"
                    f"color: #f85149;"
                    f"line-height: 1.3;"
                    f"margin-top: 0.25rem;"
                    f"'>❌ Invalid</div>",
                    unsafe_allow_html=True,
                )
                validation_errors.append(
                    f"**{uploaded_file.name}:** {validation_message}"
                )

        # ---- Row 2: full-width preview expander ----
        with st.expander(f"👁️ Preview source — {uploaded_file.name}"):
            _render_scrollable_xml(file_content, height_px=300)

        # ---- Collect valid files for processing ----
        if is_valid:
            file_configs.append(
                {
                    "file": uploaded_file,
                    "doc_type": doc_type,
                }
            )

        st.divider()

# Validation errors grouped in one compact, scrollable expander
if validation_errors:
    with st.expander("⚠️ Validation Errors — click to expand", expanded=True):
        # Wrap errors in a height-constrained scrollable div
        error_html = "".join(
            f"<p style='color:#faad14; margin:0.3rem 0;'>⚠️ {err}</p>"
            for err in validation_errors
        )
        st.markdown(
            f"""
            <div style="
                max-height: 200px;
                overflow-y: auto;
                border: 1px solid #444;
                border-radius: 6px;
                padding: 0.75rem;
                background-color: #1a1a2e;
                font-size: 0.9rem;
            ">
                {error_html}
            </div>
            """,
            unsafe_allow_html=True,
        )

# File summary bar
valid_count = len(file_configs)
invalid_count = len(uploaded_files) - valid_count

if valid_count > 0:
    st.info(
        f"📊 **Summary:** {valid_count} valid file(s) ready for processing"
        + (f", {invalid_count} invalid file(s) will be skipped." if invalid_count else ".")
    )
else:
    st.warning("⚠️ No valid cXML files to process. Please upload valid cXML documents.")

# --- Anonymize button — disabled when nothing valid to process ---
dry_run = st.checkbox(
    "🔍 Dry-run mode — preview substitutions without downloading",
    value=False,
    help="Runs the full anonymization pipeline and shows you exactly what would change, but does not produce downloadable files.",
    disabled=(valid_count == 0),
)

button_label = "🔍 Preview Changes (Dry-run)" if dry_run else "🚀 Anonymize All Documents"
if not st.button(
    button_label,
    type="primary",
    use_container_width=True,
    disabled=(valid_count == 0),
):
    st.stop()

anonymized_files: dict[str, str] = {}
processing_logs: dict[str, dict[str, any]] = {}
errors: list[str] = []

progress_bar = st.progress(0)
status_text = st.empty()

for i, config in enumerate(file_configs):
    file = config["file"]
    status_text.text(f"{'Previewing' if dry_run else 'Processing'} {file.name}…")

    try:
        xml_content = file.getvalue().decode("utf-8")
        anonymized_content, log, region_code, detection_method = process_cxml_content(xml_content)
        region_display = REGIONAL_PROFILES[region_code]["display_name"]
        stem = Path(file.name).stem
        suffix = Path(file.name).suffix  # preserves .xml or .txt
        output_filename = f"anonymized_{stem}{suffix}"
        if not dry_run:
            anonymized_files[output_filename] = anonymized_content
        processing_logs[output_filename] = {
            "log": log,
            "region": region_display,
            "detection_method": detection_method,
            "processed_at": datetime.now().isoformat(timespec="seconds"),
            "dry_run": dry_run,
        }
    except ValueError as e:
        errors.append(f"❌ **{file.name}** — Validation error: {e}")
    except Exception as e:
        errors.append(f"❌ **{file.name}** — {type(e).__name__}: {e}")

    progress_bar.progress((i + 1) / len(file_configs))

status_text.empty()
progress_bar.empty()

if errors:
    for error in errors:
        st.error(error)

if not processing_logs:
    st.stop()

if dry_run:
    st.info(
        f"🔍 **Dry-run complete** — {len(processing_logs)} file(s) analysed. "
        "No files have been modified or made available for download. "
        "Uncheck **Dry-run mode** and click the button again to produce anonymized files."
    )
else:
    st.success(f"✅ Successfully anonymized {len(anonymized_files)} file(s)!")

# --- Download section (skipped in dry-run) ---
if not dry_run and anonymized_files:
    st.subheader("📥 Download Anonymized Files")

    if len(anonymized_files) > 1:
        zip_file = create_zip_file(anonymized_files)
        st.download_button(
            label="📦 Download All as ZIP",
            data=zip_file,
            file_name="anonymized_cxml_files.zip",
            mime="application/zip",
            use_container_width=True,
        )
        st.divider()

    st.markdown("**Individual Files:**")
    for filename, content in anonymized_files.items():
        col1, col2 = st.columns([3, 1])
        with col1:
            with st.expander(f"👁️ Preview: {filename}"):
                _render_scrollable_xml(content, height_px=400)
        with col2:
            st.download_button(
                label="📥 Download",
                data=content,
                file_name=filename,
                mime="application/xml",
                key=f"download_{filename}",
            )

# --- Processing summary ---
st.divider()
st.subheader("📋 Processing Summary")
st.caption("Auto-detected region, timestamp, and every field substitution made across all files.")

for filename, info in processing_logs.items():
    log = info["log"]
    region = info["region"]
    detection_method = info["detection_method"]
    processed_at = info["processed_at"]
    is_dry_run = info["dry_run"]
    dry_run_badge = " 🔍 Dry-run" if is_dry_run else ""
    unique_log = list(dict.fromkeys(log))  # Preserves order, removes duplicates
    with st.expander(f"🔍 {filename} — {region} — {len(unique_log)} substitution(s){dry_run_badge}"):
        st.caption(f"Processed at: {processed_at} | Region detected via: {detection_method}")
        if unique_log:
            for entry in unique_log:
                st.markdown(f"- {entry}")
        else:
            st.info("No substitutions were recorded for this file.")

# --- Footer ---
st.divider()
st.markdown(
    "<p style='text-align: center; color: gray;'>cXML Anonymizer Tool | Test Central Preparation</p>",
    unsafe_allow_html=True,
)