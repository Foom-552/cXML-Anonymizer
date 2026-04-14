import hashlib
import io
import html as _html
import re
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
# HARDENED lxml PARSER  (FIX #1 — SSRF / external entity via lxml)
# ---------------------------------------------------------------------------
# defusedxml is used as a security gate, but lxml re-parses independently and,
# by default, will resolve external entities and DTD network references.
# This single parser instance is used everywhere lxml touches user content.
_SAFE_PARSER = lxml_ET.XMLParser(
    resolve_entities=False,   # never expand entity references
    no_network=True,          # block all network I/O during parse
    load_dtd=False,           # do not load or process any DTD
    huge_tree=False,          # reject deeply-nested / billion-node documents
)


# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

# Generic / universal anonymization rules.
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

# FIX #11 — moved out of detect_region() so it is not rebuilt on every call.
COUNTRY_NAME_TO_REGION: dict[str, str] = {
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

DEFAULT_REGION = "AU"

SENSITIVE_ATTR_NAMES: set[str] = {"name", "email", "phone", "contact", "firstName", "lastName"}

PRESERVE_EXTRINSIC_NAMES: set[str] = {
    "extLineNumber",
    "materialStorageLocation",
    "warehouseStorageLocationNo",
    "incoTerm",
    "incoTermDesc",
    "incoTermLocation",
    "CompanyCode",
    "PurchaseGroup",
    "PurchaseOrganization",
    "Ariba.invoicingAllowed",
    "AribaNetwork.PaymentTermsExplanation",
    "transactionCategoryOrType",
}

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
    "supplementNo": "ANONYMIZED-PHONE",
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

# Pre-compiled regex for _insert_doctype (FIX #7)
_XML_DECL_RE = re.compile(r"<\?xml[^?]*\?>")

# Pre-compiled regex for safe filename stems (FIX #4)
_UNSAFE_STEM_CHARS = re.compile(r"[^\w\-.]")

# Batch upload limits
MAX_FILES = 50
MAX_FILE_SIZE_MB = 10
# FIX #5 — aggregate memory cap prevents a single malicious batch from
# exhausting server memory (50 × 10 MB raw → up to ~2.5 GB after lxml parse).
MAX_TOTAL_BATCH_MB = 50


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def _stable_id(value: str) -> str:
    """Return a short, stable, collision-resistant hex string for *value*.

    Used for CSS IDs and Streamlit widget keys.
    FIX #8 — replaces abs(hash(...)) which is non-deterministic across processes.
    """
    return hashlib.sha1(value.encode()).hexdigest()[:12]


def _deduplicate_log(log: list[dict]) -> list[dict]:
    """Remove duplicate log entries while preserving insertion order.

    FIX #12 — extracted from _render_summary_table and the UI expander label
    so the logic lives in exactly one place.
    """
    seen: set[tuple] = set()
    unique: list[dict] = []
    for entry in log:
        key = (entry["field"], entry["original"], entry["anonymized"])
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    return unique


def _sanitize_stem(raw_name: str, max_len: int = 64) -> str:
    """Return a filesystem-safe stem derived from *raw_name*.

    FIX #4 — prevents path-traversal sequences such as ../../etc/passwd
    from appearing in output filenames or HTML.
    """
    stem = Path(raw_name).stem
    safe = _UNSAFE_STEM_CHARS.sub("_", stem)
    return safe[:max_len] or "file"


def _looks_like_xml(content: str) -> bool:
    """Return True only when *content* plausibly contains XML.

    FIX #3 — guards against non-XML files renamed to .xml/.txt that would
    otherwise be handed directly to the parsers.
    """
    stripped = content.lstrip()
    return stripped.startswith("<?xml") or stripped.startswith("<cXML")


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
    # Single pass — collect Country and Money elements to avoid three full tree scans.
    country_els: list[lxml_ET._Element] = []
    money_els: list[lxml_ET._Element] = []
    for el in root.iter():
        local = lxml_ET.QName(el.tag).localname
        if local == "Country":
            country_els.append(el)
        elif local == "Money":
            money_els.append(el)

    # 1. isoCountryCode attribute
    for el in country_els:
        code = el.get("isoCountryCode", "").upper()
        if code in ISO_COUNTRY_TO_REGION:
            return ISO_COUNTRY_TO_REGION[code], f"isoCountryCode='{code}'"

    # 2. currency attribute on <Money>
    for el in money_els:
        currency = el.get("currency", "").upper()
        if currency in CURRENCY_TO_REGION:
            return CURRENCY_TO_REGION[currency], f"currency='{currency}'"

    # 3. Country text content  (FIX #11 — map is now a module-level constant)
    for el in country_els:
        if el.text:
            name = el.text.strip().lower()
            if name in COUNTRY_NAME_TO_REGION:
                return COUNTRY_NAME_TO_REGION[name], f"country name='{el.text.strip()}'"

    # 4. Default fallback
    return DEFAULT_REGION, "fallback default"


# ---------------------------------------------------------------------------
# VALIDATION
# ---------------------------------------------------------------------------

def validate_cxml_file(xml_content: str) -> tuple[bool, str, str | None]:
    """Validate an uploaded file as a well-formed, structurally correct cXML document.

    Uses defusedxml as a security gate, then lxml (via the hardened parser) for
    structural inspection.

    Returns:
        (is_valid, message, document_type)
        document_type is None when is_valid is False.
    """
    # FIX #3 — content sniff before any XML parsing
    if not _looks_like_xml(xml_content):
        return False, "File does not appear to contain XML content.", None

    # Security gate — defusedxml raises on entity bombs / malicious constructs
    try:
        safe_ET.fromstring(xml_content.encode())
    except Exception as e:
        return False, f"XML security check failed: {e}", None

    # Structural validation via lxml with the hardened parser
    # FIX #9 — each exception class now has its own handler so unexpected
    # errors surface as clean validation failures rather than unhandled exceptions.
    try:
        root = lxml_ET.fromstring(xml_content.encode(), parser=_SAFE_PARSER)
    except lxml_ET.XMLSyntaxError as e:
        return False, f"XML parsing error: {e}", None
    except Exception as e:
        return False, f"Unexpected parse error ({type(e).__name__}): {e}", None

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
# ANONYMIZATION
# ---------------------------------------------------------------------------

def apply_header_template(root: lxml_ET._Element) -> list[dict]:
    """Overwrite cXML envelope attributes and the Header / OrderRequestHeader
    with sanitised placeholder values.

    Returns a list of dicts with keys: field, original, anonymized.
    """
    log: list[dict] = []

    for attr, new_val in [
        ("payloadID", "#PAYLOADID#"),
        ("timestamp", "2026-01-01T14:53:00-07:00"),
        ("version", "1.2.069"),
    ]:
        old_val = root.get(attr)
        root.set(attr, new_val)
        # FIX #13 — distinguish "attribute absent" from "attribute present but empty"
        if old_val is None:
            log.append({"field": f"<cXML {attr}>", "original": "(not present — added)", "anonymized": new_val})
        elif old_val != new_val:
            log.append({"field": f"<cXML {attr}>", "original": old_val, "anonymized": new_val})

    old_lang = root.get("{http://www.w3.org/XML/1998/namespace}lang", "")
    root.set("{http://www.w3.org/XML/1998/namespace}lang", "en-US")
    if old_lang != "en-US":
        log.append({"field": "<cXML xml:lang>", "original": old_lang or "(not present — added)", "anonymized": "en-US"})

    header = root.find("Header")
    if header is not None:
        for parent_tag, identity, domain in [
            ("From", "#SENDERID#", "NetworkId"),
            ("To", "#RECEIVERID#", "NetworkId"),
            ("Sender", "#PROVIDERID#", "NetworkID"),
        ]:
            parent_el = header.find(parent_tag)
            if parent_el is not None:
                old_identity = ""
                old_domain = ""
                for cred in parent_el.findall("Credential"):
                    old_domain = cred.get("domain", "")
                    id_el = cred.find("Identity")
                    if id_el is not None and id_el.text:
                        old_identity = id_el.text
                        break
                _replace_credential(parent_el, identity, domain)
                log.append({
                    "field": f"<{parent_tag}/Credential/Identity>",
                    "original": old_identity or "(not present — added)",
                    "anonymized": identity,
                })
                if old_domain and old_domain != domain:
                    log.append({
                        "field": f"<{parent_tag}/Credential domain>",
                        "original": old_domain,
                        "anonymized": domain,
                    })

        sender_tag = header.find("Sender")
        if sender_tag is not None:
            user_agent = sender_tag.find("UserAgent")
            if user_agent is not None:
                old_ua = user_agent.text or ""
                user_agent.text = "Ariba SN"
                if old_ua != "Ariba SN":
                    log.append({
                        "field": "<Sender/UserAgent>",
                        "original": old_ua or "(empty)",
                        "anonymized": "Ariba SN",
                    })

    request_tag = root.find("Request")
    if request_tag is not None:
        old_deploy = request_tag.get("deploymentMode", "")
        request_tag.set("deploymentMode", "test")
        if old_deploy != "test":
            log.append({
                "field": "<Request deploymentMode>",
                "original": old_deploy or "(not present — added)",
                "anonymized": "test",
            })

        orh = request_tag.find(".//OrderRequestHeader")
        if orh is not None:
            for attr, new_val in [
                ("orderDate", "#DATETIME#"),
                ("orderID", "#DOCUMENTID#"),
                ("orderType", "regular"),
                ("orderVersion", "1"),
                ("type", "new"),
            ]:
                old_val = orh.get(attr)
                orh.set(attr, new_val)
                if old_val is None:
                    log.append({
                        "field": f"<OrderRequestHeader {attr}>",
                        "original": "(not present — added)",
                        "anonymized": new_val,
                    })
                elif old_val != new_val:
                    log.append({
                        "field": f"<OrderRequestHeader {attr}>",
                        "original": old_val,
                        "anonymized": new_val,
                    })

    return log


def _replace_credential(parent: lxml_ET._Element, identity: str, domain: str) -> None:
    """Remove all Credential / Correspondent children from *parent* and insert
    a single sanitised Credential element.

    FIX #14 — removed the dead None guard; all callers already check for None.
    """
    for child in list(parent):
        if child.tag in ("Credential", "Correspondent"):
            parent.remove(child)
    cred = lxml_ET.SubElement(parent, "Credential")
    cred.set("domain", domain)
    lxml_ET.SubElement(cred, "Identity").text = identity


def anonymize_elements(element: lxml_ET._Element, profile: dict[str, str]) -> list[dict]:
    """Recursively traverse *element* and apply anonymization rules from *profile*.

    Returns a list of dicts with keys: field, original, anonymized.
    """
    log: list[dict] = []

    for child in element:
        local_tag = lxml_ET.QName(child.tag).localname

        # --- Element text substitution ---
        if local_tag in profile:
            old = child.text or ""
            child.text = profile[local_tag]
            if old != child.text:
                log.append({
                    "field": f"<{local_tag}> text",
                    "original": old,
                    "anonymized": profile[local_tag],
                })

        # Special-case: Money currency attribute
        if local_tag == "Money" and "currency" in profile:
            old_curr = child.get("currency", "")
            child.set("currency", profile["currency"])
            if old_curr != profile["currency"]:
                log.append({
                    "field": "<Money currency>",
                    "original": old_curr,
                    "anonymized": profile["currency"],
                })

        # Special-case: Country isoCountryCode attribute
        if local_tag == "Country" and "isoCountryCode" in profile:
            old_code = child.get("isoCountryCode", "")
            child.set("isoCountryCode", profile["isoCountryCode"])
            if old_code != profile["isoCountryCode"]:
                log.append({
                    "field": "<Country isoCountryCode>",
                    "original": old_code,
                    "anonymized": profile["isoCountryCode"],
                })

        # Extrinsic handling
        if local_tag == "Extrinsic":
            extrinsic_name = child.get("name", "")
            if extrinsic_name in PRESERVE_EXTRINSIC_NAMES:
                log.append({
                    "field": f'<Extrinsic name="{extrinsic_name}">',
                    "original": child.text or "",
                    "anonymized": "(preserved — unchanged)",
                })
            else:
                anonymized_value = EXTRINSIC_ANONYMIZATION_MAP.get(
                    extrinsic_name, "ANONYMIZED_EXTRINSIC_VALUE"
                )
                old_text = child.text or ""
                child.text = anonymized_value
                if old_text != anonymized_value:
                    label = f'name="{extrinsic_name}"' if extrinsic_name else "(no name)"
                    log.append({
                        "field": f"<Extrinsic {label}>",
                        "original": old_text,
                        "anonymized": anonymized_value,
                    })

        # IdReference identifiers are always scrubbed
        if local_tag == "IdReference" and "identifier" in child.attrib:
            old_id = child.get("identifier", "")
            child.set("identifier", "ANONYMIZED_IDENTIFIER")
            log.append({
                "field": "<IdReference identifier>",
                "original": old_id,
                "anonymized": "ANONYMIZED_IDENTIFIER",
            })

        # --- Attribute substitution ---
        for attr_name in list(child.attrib):
            local_attr = lxml_ET.QName(attr_name).localname
            # Never overwrite the Extrinsic name= attribute
            if local_tag == "Extrinsic" and local_attr == "name":
                continue
            if local_attr in profile:
                old_val = child.get(attr_name, "")
                child.set(attr_name, profile[local_attr])
                log.append({
                    "field": f"<{local_tag} {local_attr}>",
                    "original": old_val,
                    "anonymized": profile[local_attr],
                })
            elif local_attr.lower() in SENSITIVE_ATTR_NAMES:
                old_val = child.get(attr_name, "")
                child.set(attr_name, "ANONYMIZED")
                log.append({
                    "field": f"<{local_tag} {local_attr}> (sensitive)",
                    "original": old_val,
                    "anonymized": "ANONYMIZED",
                })

        log.extend(anonymize_elements(child, profile))

    return log


def _insert_doctype(xml_string: str) -> str:
    """Insert the cXML DOCTYPE declaration immediately after the XML declaration.

    FIX #7 — uses a compiled regex instead of a fragile str.index('?>') search,
    which could misfire on processing instructions or comments.
    """
    match = _XML_DECL_RE.search(xml_string)
    if match:
        end = match.end()
        return xml_string[:end] + "\n" + CXML_DOCTYPE + xml_string[end:]
    return CXML_DOCTYPE + "\n" + xml_string


def process_cxml_content(
    xml_content: str,
    region_code: str | None = None,
    detection_method: str | None = None,
) -> tuple[str, list[dict], str, str]:
    """Parse, anonymize and serialise a cXML document.

    FIX #6 — accepts a pre-detected (region_code, detection_method) pair so the
    caller can pass in the result already computed during the upload display loop,
    avoiding a redundant third lxml parse per file.  When both are None the
    region is auto-detected here as before.

    Returns:
        (anonymized_xml_string, substitution_log, region_code, detection_method)
    """
    # FIX #1 — use the hardened parser everywhere lxml touches user content
    root: lxml_ET._Element = lxml_ET.fromstring(xml_content.encode(), parser=_SAFE_PARSER)

    if region_code is None or detection_method is None:
        region_code, detection_method = detect_region(root)

    active_profile: dict[str, str] = {**GENERIC_ANONYMIZATION_MAP, **REGIONAL_PROFILES[region_code]}
    active_profile.pop("display_name", None)

    header_log = apply_header_template(root)
    element_log = anonymize_elements(root, active_profile)
    log = header_log + element_log

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
    """Display XML content inside a scrollable <div> with a fixed max height."""
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
# HELPER: render the processing summary as a scrollable, copyable table
# ---------------------------------------------------------------------------

def _render_summary_table(log: list[dict], filename: str, height_px: int = 400) -> None:
    """Render the substitution log as a scrollable HTML table with a TSV download.

    FIX #12 — deduplication delegated to _deduplicate_log().
    FIX #8  — CSS table ID uses _stable_id() instead of abs(hash()).
    FIX #10 — Streamlit widget key uses _stable_id() instead of a mutable counter.
    """
    unique_log = _deduplicate_log(log)

    if not unique_log:
        st.info("No substitutions were recorded for this file.")
        return

    rows_html = ""
    for idx, entry in enumerate(unique_log, 1):
        field = _html.escape(entry["field"])
        original = _html.escape(entry["original"]) if entry["original"] else "<em>(empty)</em>"
        anonymized = _html.escape(entry["anonymized"])
        rows_html += (
            f"<tr>"
            f"<td style='padding:6px 10px; border-bottom:1px solid #333; color:#aaa; "
            f"text-align:center; white-space:nowrap;'>{idx}</td>"
            f"<td style='padding:6px 10px; border-bottom:1px solid #333; color:#79c0ff; "
            f"font-family:monospace; font-size:0.82rem; white-space:nowrap;'>{field}</td>"
            f"<td style='padding:6px 10px; border-bottom:1px solid #333; color:#f85149; "
            f"font-family:monospace; font-size:0.82rem; white-space:nowrap;'>{original}</td>"
            f"<td style='padding:6px 10px; border-bottom:1px solid #333; color:#3fb950; "
            f"font-family:monospace; font-size:0.82rem; white-space:nowrap;'>{anonymized}</td>"
            f"</tr>"
        )

    # FIX #8 — stable, collision-resistant CSS ID
    table_id = f"summary-table-{_stable_id(filename)}"

    table_html = f"""
    <style>
        #{table_id} {{
            max-height: {height_px}px;
            overflow-x: auto !important;
            overflow-y: auto !important;
            display: block;
            width: 100%;
            border: 1px solid #444;
            border-radius: 6px;
            background-color: #0d1117;
        }}
        #{table_id}::-webkit-scrollbar {{ width: 10px; height: 10px; }}
        #{table_id}::-webkit-scrollbar-track {{ background: #161b22; border-radius: 6px; }}
        #{table_id}::-webkit-scrollbar-thumb {{
            background: #484f58; border-radius: 6px; border: 2px solid #161b22;
        }}
        #{table_id}::-webkit-scrollbar-thumb:hover {{ background: #6e7681; }}
        #{table_id}::-webkit-scrollbar-corner {{ background: #161b22; }}
    </style>
    <div id="{table_id}">
        <table style="width: max-content; min-width: 100%; border-collapse: collapse; font-size: 0.85rem;">
            <thead>
                <tr style="background-color: #161b22; position: sticky; top: 0; z-index: 1;">
                    <th style="padding:8px 10px; border-bottom:2px solid #444; color:#c9d1d9;
                        text-align:center; width:50px; white-space:nowrap;
                        position:sticky; top:0; background-color:#161b22;">#</th>
                    <th style="padding:8px 10px; border-bottom:2px solid #444; color:#c9d1d9;
                        text-align:left; min-width:250px; white-space:nowrap;
                        position:sticky; top:0; background-color:#161b22;">Field</th>
                    <th style="padding:8px 10px; border-bottom:2px solid #444; color:#c9d1d9;
                        text-align:left; min-width:280px; white-space:nowrap;
                        position:sticky; top:0; background-color:#161b22;">Original Value</th>
                    <th style="padding:8px 10px; border-bottom:2px solid #444; color:#c9d1d9;
                        text-align:left; min-width:280px; white-space:nowrap;
                        position:sticky; top:0; background-color:#161b22;">Anonymized Value</th>
                </tr>
            </thead>
            <tbody>{rows_html}</tbody>
        </table>
    </div>
    """
    st.markdown(table_html, unsafe_allow_html=True)

    tsv_lines = ["#\tField\tOriginal Value\tAnonymized Value"]
    for idx, entry in enumerate(unique_log, 1):
        tsv_lines.append(f"{idx}\t{entry['field']}\t{entry['original']}\t{entry['anonymized']}")
    tsv_text = "\n".join(tsv_lines)

    # FIX #10 — deterministic widget key; no mutable session-state counter needed
    st.download_button(
        label="📋 Download as TSV (paste into Excel / Sheets)",
        data=tsv_text,
        file_name=f"substitution_summary_{filename}.tsv",
        mime="text/tab-separated-values",
        key=f"tsv_{_stable_id(filename)}",
    )
    st.caption(f"{len(unique_log)} unique substitution(s)")


# ---------------------------------------------------------------------------
# STREAMLIT UI
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="cXML Anonymizer Tool",
    page_icon="🔒",
    layout="wide",
)

st.markdown(
    """
    <style>
    div[data-testid="stExpander"] details div[data-testid="stMarkdownContainer"] {
        max-height: 300px;
        overflow-y: auto;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

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
uploader_key = f"file_uploader_{st.session_state.clear_trigger}"

uploaded_files = st.file_uploader(
    "Upload your cXML files",
    type=["xml", "txt"],
    accept_multiple_files=True,
    help="Select one or more cXML documents to anonymize. Accepts .xml and .txt files containing cXML content.",
    key=uploader_key,
)

if st.session_state.clear_trigger:
    st.session_state.clear_trigger = False

if not uploaded_files:
    st.info("👆 Please upload one or more cXML files to get started. Accepted formats: .xml and .txt")
    st.stop()

oversized = [f.name for f in uploaded_files if len(f.getvalue()) > MAX_FILE_SIZE_MB * 1024 * 1024]

if len(uploaded_files) > MAX_FILES:
    st.error(f"❌ Maximum {MAX_FILES} files allowed per batch. You uploaded {len(uploaded_files)}.")
    st.stop()

if oversized:
    # FIX #2 — escape filenames before embedding in any message rendered as HTML;
    # here st.error uses markdown so escaping is still good practice.
    safe_names = ", ".join(_html.escape(n) for n in oversized)
    st.error(
        f"❌ The following file(s) exceed the {MAX_FILE_SIZE_MB} MB size limit "
        f"and cannot be processed: {safe_names}"
    )
    st.stop()

total_bytes = sum(len(f.getvalue()) for f in uploaded_files)
if total_bytes > MAX_TOTAL_BATCH_MB * 1024 * 1024:
    st.error(
        f"❌ Total upload size ({total_bytes / 1024 / 1024:.1f} MB) exceeds the "
        f"{MAX_TOTAL_BATCH_MB} MB batch limit. Please upload fewer or smaller files."
    )
    st.stop()

# --- Per-file configuration ---
st.divider()
st.subheader(f"📁 {len(uploaded_files)} File(s) Uploaded")

file_configs: list[dict] = []
validation_errors: list[str] = []

for i, uploaded_file in enumerate(uploaded_files):
    raw = uploaded_file.getvalue()
    try:
        file_content = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        is_valid, validation_message, doc_type = False, f"File is not valid UTF-8: {exc}", None
        file_content = ""
    else:
        is_valid, validation_message, doc_type = validate_cxml_file(file_content)

    # FIX #6 — detect region once here and store it in file_configs so
    # process_cxml_content does not need to parse a third time per file.
    detected_code = DEFAULT_REGION
    detected_by = "fallback default"
    detected_region_label = REGIONAL_PROFILES[DEFAULT_REGION]["display_name"]

    if is_valid:
        try:
            root_preview = lxml_ET.fromstring(file_content.encode(), parser=_SAFE_PARSER)
            detected_code, detected_by = detect_region(root_preview)
            detected_region_label = REGIONAL_PROFILES[detected_code]["display_name"]
        except Exception:
            pass  # keep defaults set above

    with st.container():
        col1, col2, col3 = st.columns([2, 2, 1])

        # FIX #2 — escape filename before inserting into unsafe_allow_html blocks
        safe_display_name = _html.escape(uploaded_file.name)

        with col1:
            file_size = len(raw) / 1024
            st.markdown(
                f"**📄 {safe_display_name}**  \n"
                f"<span style='color:gray; font-size:0.85rem;'>"
                f"Size: {file_size:.1f} KB</span>",
                unsafe_allow_html=True,
            )

        with col2:
            if is_valid:
                safe_region_label = _html.escape(detected_region_label)
                safe_detected_by = _html.escape(detected_by)
                st.markdown(
                    f"🌍 **{safe_region_label}**  \n"
                    f"<span style='color:gray; font-size:0.85rem;'>"
                    f"Detected via: {safe_detected_by}</span>",
                    unsafe_allow_html=True,
                )
            else:
                st.empty()

        with col3:
            if is_valid:
                safe_doc_type = _html.escape(doc_type or "")
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
                    f"'>✅ {safe_doc_type}</div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    "<div style='"
                    "background-color: #4a1a1a;"
                    "border: 1px solid #d73a49;"
                    "border-radius: 6px;"
                    "padding: 0.35rem 0.6rem;"
                    "text-align: center;"
                    "font-size: 0.85rem;"
                    "color: #f85149;"
                    "line-height: 1.3;"
                    "margin-top: 0.25rem;"
                    "'>❌ Invalid</div>",
                    unsafe_allow_html=True,
                )
                validation_errors.append(
                    f"**{safe_display_name}:** {_html.escape(validation_message)}"
                )

        with st.expander(f"👁️ Preview source — {safe_display_name}"):
            _render_scrollable_xml(file_content, height_px=300)

        if is_valid:
            file_configs.append({
                "file": uploaded_file,
                "doc_type": doc_type,
                # FIX #6 — carry pre-detected region through to avoid re-parsing
                "region_code": detected_code,
                "detection_method": detected_by,
                "xml_content": file_content,
            })

        st.divider()

if validation_errors:
    with st.expander("⚠️ Validation Errors — click to expand", expanded=True):
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

valid_count = len(file_configs)
invalid_count = len(uploaded_files) - valid_count

if valid_count > 0:
    st.info(
        f"📊 **Summary:** {valid_count} valid file(s) ready for processing"
        + (f", {invalid_count} invalid file(s) will be skipped." if invalid_count else ".")
    )
else:
    st.warning("⚠️ No valid cXML files to process. Please upload valid cXML documents.")

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
processing_logs: dict[str, dict] = {}
errors: list[str] = []

progress_bar = st.progress(0)
status_text = st.empty()

for i, config in enumerate(file_configs):
    file = config["file"]
    status_text.text(f"{'Previewing' if dry_run else 'Processing'} {file.name}…")

    try:
        xml_content = config["xml_content"]

        # FIX #6 — pass pre-detected region so process_cxml_content skips re-detection
        anonymized_content, log, region_code, detection_method = process_cxml_content(
            xml_content,
            region_code=config["region_code"],
            detection_method=config["detection_method"],
        )
        region_display = REGIONAL_PROFILES[region_code]["display_name"]

        # FIX #4 — sanitize stem to prevent path traversal in output filenames
        safe_stem = _sanitize_stem(file.name)
        suffix = Path(file.name).suffix
        output_filename = f"anonymized_{safe_stem}{suffix}"

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
        errors.append(f"❌ **{_html.escape(file.name)}** — Validation error: {e}")
    except Exception as e:
        errors.append(f"❌ **{_html.escape(file.name)}** — {type(e).__name__}: {e}")

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
        safe_filename = _html.escape(filename)   # FIX #2
        col1, col2 = st.columns([3, 1])
        with col1:
            with st.expander(f"👁️ Preview: {safe_filename}"):
                _render_scrollable_xml(content, height_px=1000)
        with col2:
            st.download_button(
                label="📥 Download",
                data=content,
                file_name=filename,
                mime="application/xml",
                key=f"download_{_stable_id(filename)}",  # FIX #8
            )

# --- Processing summary ---
st.divider()
st.subheader("📋 Processing Summary")
st.caption("Auto-detected region, timestamp, and every field substitution with original and anonymized values.")

for filename, info in processing_logs.items():
    log = info["log"]
    region = info["region"]
    detection_method = info["detection_method"]
    processed_at = info["processed_at"]
    is_dry_run = info["dry_run"]
    dry_run_badge = " 🔍 Dry-run" if is_dry_run else ""

    # FIX #12 — use shared helper; no duplicated deduplication logic here
    unique_count = len(_deduplicate_log(log))
    safe_filename = _html.escape(filename)   # FIX #2

    with st.expander(
        f"🔍 {safe_filename} — {_html.escape(region)} — {unique_count} substitution(s){dry_run_badge}"
    ):
        st.caption(
            f"Processed at: {processed_at} | Region detected via: {_html.escape(detection_method)}"
        )
        _render_summary_table(log, filename, height_px=700)

# --- Footer ---
st.divider()
st.markdown(
    "<p style='text-align: center; color: gray;'>cXML Anonymizer Tool | Test Central Preparation</p>",
    unsafe_allow_html=True,
)