"""cXML Anonymizer — Streamlit app for anonymizing cXML transactional documents.

Sections (in order):
  - Imports & security setup  — hardened lxml parser, defusedxml gate
  - Configuration             — COUNTRY_PROFILES, anonymization maps, limits
  - DocumentMeta              — frozen dataclass for document type/subtype
  - Helpers                   — _stable_id, _sanitize_stem, _looks_like_xml
  - Region detection          — detect_country(), _resolve_profile()
  - Validation                — validate_cxml_file()
  - Anonymization             — apply_header_template(), anonymize_elements(), process_cxml_content()
  - UI rendering              — scrollable XML, summary tables, theme CSS
  - Streamlit app             — file upload, processing, download, summary
"""
import hashlib
import io
import html as _html
import logging
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import streamlit as st

_log = logging.getLogger(__name__)

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

# Per-country profiles supply locale-specific anonymized replacement values.
# Each country maps to a region for grouping/display.  Countries without a
# dedicated profile fall back to their region's default via REGION_DEFAULTS.
COUNTRY_PROFILES: dict[str, dict[str, str]] = {
    # ── APAC (default: AU) ──────────────────────────────────────────────
    "AU": {
        "display_name": "Australia (APAC)", "region": "APAC",
        "City": "Anonymized City", "State": "WA", "PostalCode": "6000",
        "Country": "Australia", "isoCountryCode": "AU",
        "Money": "1.00", "currency": "AUD", "Number": "0891234567",
    },
    "NZ": {
        "display_name": "New Zealand (APAC)", "region": "APAC",
        "City": "Anonymized City", "State": "Auckland", "PostalCode": "1010",
        "Country": "New Zealand", "isoCountryCode": "NZ",
        "Money": "1.00", "currency": "NZD", "Number": "093012345",
    },
    "IN": {
        "display_name": "India (APAC)", "region": "APAC",
        "City": "Anonymized City", "State": "Maharashtra", "PostalCode": "400001",
        "Country": "India", "isoCountryCode": "IN",
        "Money": "1.00", "currency": "INR", "Number": "02212345678",
    },
    "CN": {
        "display_name": "China (APAC)", "region": "APAC",
        "City": "Anonymized City", "State": "Shanghai", "PostalCode": "200000",
        "Country": "China", "isoCountryCode": "CN",
        "Money": "1.00", "currency": "CNY", "Number": "02112345678",
    },
    "SG": {
        "display_name": "Singapore (APAC)", "region": "APAC",
        "City": "Anonymized City", "State": "SG", "PostalCode": "018956",
        "Country": "Singapore", "isoCountryCode": "SG",
        "Money": "1.00", "currency": "SGD", "Number": "61234567",
    },
    "KR": {
        "display_name": "South Korea (APAC)", "region": "APAC",
        "City": "Anonymized City", "State": "Seoul", "PostalCode": "04524",
        "Country": "Korea, Republic of", "isoCountryCode": "KR",
        "Money": "1.00", "currency": "KRW", "Number": "0212345678",
    },
    "TH": {
        "display_name": "Thailand (APAC)", "region": "APAC",
        "City": "Anonymized City", "State": "Bangkok", "PostalCode": "10110",
        "Country": "Thailand", "isoCountryCode": "TH",
        "Money": "1.00", "currency": "THB", "Number": "021234567",
    },
    "ID": {
        "display_name": "Indonesia (APAC)", "region": "APAC",
        "City": "Anonymized City", "State": "Jakarta", "PostalCode": "10110",
        "Country": "Indonesia", "isoCountryCode": "ID",
        "Money": "1.00", "currency": "IDR", "Number": "02112345678",
    },
    "PH": {
        "display_name": "Philippines (APAC)", "region": "APAC",
        "City": "Anonymized City", "State": "Metro Manila", "PostalCode": "1000",
        "Country": "Philippines", "isoCountryCode": "PH",
        "Money": "1.00", "currency": "PHP", "Number": "0281234567",
    },
    "MY": {
        "display_name": "Malaysia (APAC)", "region": "APAC",
        "City": "Anonymized City", "State": "Kuala Lumpur", "PostalCode": "50450",
        "Country": "Malaysia", "isoCountryCode": "MY",
        "Money": "1.00", "currency": "MYR", "Number": "0312345678",
    },
    # ── NAMAR (default: US) ─────────────────────────────────────────────
    "US": {
        "display_name": "United States (NAMAR)", "region": "NAMAR",
        "City": "Anonymized City", "State": "CA", "PostalCode": "90210",
        "Country": "United States", "isoCountryCode": "US",
        "Money": "1.00", "currency": "USD", "Number": "555-555-5555",
    },
    "CA": {
        "display_name": "Canada (NAMAR)", "region": "NAMAR",
        "City": "Anonymized City", "State": "ON", "PostalCode": "M5H 2N2",
        "Country": "Canada", "isoCountryCode": "CA",
        "Money": "1.00", "currency": "CAD", "Number": "416-555-5555",
    },
    "MX": {
        "display_name": "Mexico (NAMAR)", "region": "NAMAR",
        "City": "Anonymized City", "State": "CDMX", "PostalCode": "06600",
        "Country": "Mexico", "isoCountryCode": "MX",
        "Money": "1.00", "currency": "MXN", "Number": "5512345678",
    },
    # ── EMEA (default: DE) ──────────────────────────────────────────────
    "DE": {
        "display_name": "Germany (EMEA)", "region": "EMEA",
        "City": "Anonymized City", "State": "BE", "PostalCode": "10115",
        "Country": "Germany", "isoCountryCode": "DE",
        "Money": "1.00", "currency": "EUR", "Number": "03012345678",
    },
    "GB": {
        "display_name": "United Kingdom (EMEA)", "region": "EMEA",
        "City": "Anonymized City", "State": "London", "PostalCode": "SW1A 1AA",
        "Country": "United Kingdom", "isoCountryCode": "GB",
        "Money": "1.00", "currency": "GBP", "Number": "02012345678",
    },
    "FR": {
        "display_name": "France (EMEA)", "region": "EMEA",
        "City": "Anonymized City", "State": "IDF", "PostalCode": "75001",
        "Country": "France", "isoCountryCode": "FR",
        "Money": "1.00", "currency": "EUR", "Number": "0112345678",
    },
    "NL": {
        "display_name": "Netherlands (EMEA)", "region": "EMEA",
        "City": "Anonymized City", "State": "NH", "PostalCode": "1012 AB",
        "Country": "Netherlands", "isoCountryCode": "NL",
        "Money": "1.00", "currency": "EUR", "Number": "0201234567",
    },
    "CH": {
        "display_name": "Switzerland (EMEA)", "region": "EMEA",
        "City": "Anonymized City", "State": "ZH", "PostalCode": "8001",
        "Country": "Switzerland", "isoCountryCode": "CH",
        "Money": "1.00", "currency": "CHF", "Number": "0441234567",
    },
    "SE": {
        "display_name": "Sweden (EMEA)", "region": "EMEA",
        "City": "Anonymized City", "State": "Stockholm", "PostalCode": "111 22",
        "Country": "Sweden", "isoCountryCode": "SE",
        "Money": "1.00", "currency": "SEK", "Number": "081234567",
    },
    "AE": {
        "display_name": "UAE (EMEA)", "region": "EMEA",
        "City": "Anonymized City", "State": "Dubai", "PostalCode": "00000",
        "Country": "United Arab Emirates", "isoCountryCode": "AE",
        "Money": "1.00", "currency": "AED", "Number": "041234567",
    },
    "SA": {
        "display_name": "Saudi Arabia (EMEA)", "region": "EMEA",
        "City": "Anonymized City", "State": "Riyadh", "PostalCode": "11564",
        "Country": "Saudi Arabia", "isoCountryCode": "SA",
        "Money": "1.00", "currency": "SAR", "Number": "0112345678",
    },
    "ZA": {
        "display_name": "South Africa (EMEA)", "region": "EMEA",
        "City": "Anonymized City", "State": "Gauteng", "PostalCode": "2000",
        "Country": "South Africa", "isoCountryCode": "ZA",
        "Money": "1.00", "currency": "ZAR", "Number": "0111234567",
    },
    "IL": {
        "display_name": "Israel (EMEA)", "region": "EMEA",
        "City": "Anonymized City", "State": "Tel Aviv", "PostalCode": "6100000",
        "Country": "Israel", "isoCountryCode": "IL",
        "Money": "1.00", "currency": "ILS", "Number": "031234567",
    },
    "TR": {
        "display_name": "Turkey (EMEA)", "region": "EMEA",
        "City": "Anonymized City", "State": "Istanbul", "PostalCode": "34000",
        "Country": "Turkey", "isoCountryCode": "TR",
        "Money": "1.00", "currency": "TRY", "Number": "02121234567",
    },
    # ── Japan (default: JP) ─────────────────────────────────────────────
    "JP": {
        "display_name": "Japan", "region": "Japan",
        "City": "Chiyoda", "State": "Tokyo", "PostalCode": "100-0001",
        "Country": "Japan", "isoCountryCode": "JP",
        "Money": "1.00", "currency": "JPY", "Number": "0312345678",
    },
    # ── LATAM (default: BR) ─────────────────────────────────────────────
    "BR": {
        "display_name": "Brazil (LATAM)", "region": "LATAM",
        "City": "Anonymized City", "State": "SP", "PostalCode": "01000-000",
        "Country": "Brazil", "isoCountryCode": "BR",
        "Money": "1.00", "currency": "BRL", "Number": "1112345678",
    },
    "AR": {
        "display_name": "Argentina (LATAM)", "region": "LATAM",
        "City": "Anonymized City", "State": "BA", "PostalCode": "C1001",
        "Country": "Argentina", "isoCountryCode": "AR",
        "Money": "1.00", "currency": "ARS", "Number": "1112345678",
    },
    "CO": {
        "display_name": "Colombia (LATAM)", "region": "LATAM",
        "City": "Anonymized City", "State": "Bogota", "PostalCode": "110111",
        "Country": "Colombia", "isoCountryCode": "CO",
        "Money": "1.00", "currency": "COP", "Number": "6011234567",
    },
    "CL": {
        "display_name": "Chile (LATAM)", "region": "LATAM",
        "City": "Anonymized City", "State": "RM", "PostalCode": "8320000",
        "Country": "Chile", "isoCountryCode": "CL",
        "Money": "1.00", "currency": "CLP", "Number": "221234567",
    },
}

REGION_DEFAULTS: dict[str, str] = {
    "APAC": "AU",
    "NAMAR": "US",
    "EMEA": "DE",
    "Japan": "JP",
    "LATAM": "BR",
}

DEFAULT_REGION = "APAC"

# ISO 3166-1 alpha-2 country codes -> region key.
ISO_COUNTRY_TO_REGION: dict[str, str] = {
    # APAC
    "AU": "APAC", "NZ": "APAC", "IN": "APAC", "CN": "APAC", "SG": "APAC",
    "KR": "APAC", "TH": "APAC", "ID": "APAC", "PH": "APAC", "VN": "APAC",
    "MY": "APAC", "TW": "APAC", "HK": "APAC", "BD": "APAC", "LK": "APAC",
    "MM": "APAC", "KH": "APAC", "NP": "APAC",
    # North America
    "US": "NAMAR", "CA": "NAMAR",
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
    # LATAM
    "MX": "LATAM", "BR": "LATAM", "AR": "LATAM", "CO": "LATAM", "CL": "LATAM",
    "PE": "LATAM", "EC": "LATAM", "VE": "LATAM", "UY": "LATAM", "PY": "LATAM",
    "BO": "LATAM", "CR": "LATAM", "PA": "LATAM", "DO": "LATAM", "GT": "LATAM",
    "HN": "LATAM", "SV": "LATAM", "NI": "LATAM", "CU": "LATAM", "PR": "LATAM",
    "TT": "LATAM",
}

# Currency code -> (region, country) for direct per-country resolution.
CURRENCY_TO_COUNTRY: dict[str, tuple[str, str]] = {
    # APAC
    "AUD": ("APAC", "AU"), "NZD": ("APAC", "NZ"), "INR": ("APAC", "IN"),
    "CNY": ("APAC", "CN"), "SGD": ("APAC", "SG"), "KRW": ("APAC", "KR"),
    "THB": ("APAC", "TH"), "IDR": ("APAC", "ID"), "PHP": ("APAC", "PH"),
    "VND": ("APAC", "VN"), "MYR": ("APAC", "MY"), "TWD": ("APAC", "TW"),
    "HKD": ("APAC", "HK"), "BDT": ("APAC", "BD"), "LKR": ("APAC", "LK"),
    # NAMAR
    "USD": ("NAMAR", "US"), "CAD": ("NAMAR", "CA"),
    # Japan
    "JPY": ("Japan", "JP"),
    # EMEA
    "EUR": ("EMEA", "DE"), "GBP": ("EMEA", "GB"), "CHF": ("EMEA", "CH"),
    "SEK": ("EMEA", "SE"), "NOK": ("EMEA", "NO"), "DKK": ("EMEA", "DK"),
    "PLN": ("EMEA", "PL"), "CZK": ("EMEA", "CZ"), "HUF": ("EMEA", "HU"),
    "RON": ("EMEA", "RO"), "ZAR": ("EMEA", "ZA"), "AED": ("EMEA", "AE"),
    "SAR": ("EMEA", "SA"), "TRY": ("EMEA", "TR"), "ILS": ("EMEA", "IL"),
    "QAR": ("EMEA", "QA"), "BGN": ("EMEA", "BG"), "HRK": ("EMEA", "HR"),
    "RSD": ("EMEA", "RS"), "ISK": ("EMEA", "IS"), "EGP": ("EMEA", "EG"),
    "NGN": ("EMEA", "NG"), "KES": ("EMEA", "KE"), "MAD": ("EMEA", "MA"),
    "TND": ("EMEA", "TN"), "KWD": ("EMEA", "KW"), "BHD": ("EMEA", "BH"),
    "OMR": ("EMEA", "OM"), "JOD": ("EMEA", "JO"), "PKR": ("EMEA", "PK"),
    # LATAM
    "MXN": ("LATAM", "MX"), "BRL": ("LATAM", "BR"), "ARS": ("LATAM", "AR"),
    "COP": ("LATAM", "CO"), "CLP": ("LATAM", "CL"), "PEN": ("LATAM", "PE"),
    "UYU": ("LATAM", "UY"),
}

# FIX #11 — module-level constant so it is not rebuilt on every call.
COUNTRY_NAME_TO_COUNTRY: dict[str, tuple[str, str]] = {
    # APAC
    "australia": ("APAC", "AU"), "new zealand": ("APAC", "NZ"),
    "india": ("APAC", "IN"), "china": ("APAC", "CN"),
    "singapore": ("APAC", "SG"), "south korea": ("APAC", "KR"),
    "korea": ("APAC", "KR"), "thailand": ("APAC", "TH"),
    "indonesia": ("APAC", "ID"), "philippines": ("APAC", "PH"),
    "vietnam": ("APAC", "VN"), "malaysia": ("APAC", "MY"),
    "taiwan": ("APAC", "TW"), "hong kong": ("APAC", "HK"),
    "bangladesh": ("APAC", "BD"), "sri lanka": ("APAC", "LK"),
    # NAMAR
    "united states": ("NAMAR", "US"), "usa": ("NAMAR", "US"),
    "canada": ("NAMAR", "CA"),
    # Japan
    "japan": ("Japan", "JP"),
    # EMEA
    "germany": ("EMEA", "DE"), "france": ("EMEA", "FR"),
    "united kingdom": ("EMEA", "GB"), "uk": ("EMEA", "GB"),
    "england": ("EMEA", "GB"), "netherlands": ("EMEA", "NL"),
    "spain": ("EMEA", "ES"), "italy": ("EMEA", "IT"),
    "sweden": ("EMEA", "SE"), "norway": ("EMEA", "NO"),
    "denmark": ("EMEA", "DK"), "finland": ("EMEA", "FI"),
    "switzerland": ("EMEA", "CH"), "austria": ("EMEA", "AT"),
    "belgium": ("EMEA", "BE"), "ireland": ("EMEA", "IE"),
    "portugal": ("EMEA", "PT"), "poland": ("EMEA", "PL"),
    "hungary": ("EMEA", "HU"), "romania": ("EMEA", "RO"),
    "greece": ("EMEA", "GR"), "czech republic": ("EMEA", "CZ"),
    "czechia": ("EMEA", "CZ"), "croatia": ("EMEA", "HR"),
    "bulgaria": ("EMEA", "BG"), "serbia": ("EMEA", "RS"),
    "slovenia": ("EMEA", "SI"), "luxembourg": ("EMEA", "LU"),
    "iceland": ("EMEA", "IS"), "israel": ("EMEA", "IL"),
    "turkey": ("EMEA", "TR"), "south africa": ("EMEA", "ZA"),
    "united arab emirates": ("EMEA", "AE"), "uae": ("EMEA", "AE"),
    "saudi arabia": ("EMEA", "SA"), "egypt": ("EMEA", "EG"),
    "nigeria": ("EMEA", "NG"), "kenya": ("EMEA", "KE"),
    "qatar": ("EMEA", "QA"), "kuwait": ("EMEA", "KW"),
    "pakistan": ("EMEA", "PK"), "morocco": ("EMEA", "MA"),
    # LATAM
    "mexico": ("LATAM", "MX"), "brazil": ("LATAM", "BR"),
    "brasil": ("LATAM", "BR"), "argentina": ("LATAM", "AR"),
    "colombia": ("LATAM", "CO"), "chile": ("LATAM", "CL"),
    "peru": ("LATAM", "PE"), "ecuador": ("LATAM", "EC"),
    "venezuela": ("LATAM", "VE"), "uruguay": ("LATAM", "UY"),
    "paraguay": ("LATAM", "PY"), "bolivia": ("LATAM", "BO"),
    "costa rica": ("LATAM", "CR"), "panama": ("LATAM", "PA"),
}

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
# DOCUMENT METADATA
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DocumentMeta:
    """Structured metadata about a validated cXML document."""

    base_type: str
    sub_type: str = "New"
    order_version: str | None = None
    order_type: str | None = None
    has_document_reference: bool = False
    is_service_po: bool = False

    @property
    def display_label(self) -> str:
        if self.base_type == "OrderRequest":
            parts = []
            if self.sub_type != "New":
                parts.append(self.sub_type)
            if self.is_service_po:
                parts.append("Service")
            if parts:
                return f"OrderRequest ({', '.join(parts)})"
        return self.base_type

    @property
    def order_type_label(self) -> str | None:
        if self.order_type and self.order_type != "regular":
            return self.order_type
        return None

    @property
    def is_change_po(self) -> bool:
        return self.base_type == "OrderRequest" and self.sub_type == "Change"

    @property
    def is_cancel_po(self) -> bool:
        return self.base_type == "OrderRequest" and self.sub_type == "Cancel"


_ORDER_TYPE_ATTRS: dict[str, dict[str, str | None]] = {
    "blanket": {
        "releaseRequired": None,
        "parentAgreementID": "#PARENT_AGREEMENTID#",
        "parentAgreementPayloadID": "#PARENT_AGREEMENT_PAYLOADID#",
        "effectiveDate": None,
        "expirationDate": None,
    },
    "release": {
        "agreementID": "#AGREEMENTID#",
        "agreementPayloadID": "#AGREEMENT_PAYLOADID#",
    },
}


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

STABLE_ID_HEX_LENGTH = 12
MAX_STEM_LENGTH = 64


def _stable_id(value: str) -> str:
    """Return a short, stable, collision-resistant hex string for *value*.

    Used for CSS IDs and Streamlit widget keys.
    FIX #8 — replaces abs(hash(...)) which is non-deterministic across processes.
    """
    return hashlib.sha1(value.encode()).hexdigest()[:STABLE_ID_HEX_LENGTH]


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


def _sanitize_stem(raw_name: str, max_len: int = MAX_STEM_LENGTH) -> str:
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


def _replace_date_today(date_str: str) -> str:
    """Replace the date part of a cXML ISO 8601 datetime with today's date,
    preserving the original time component and timezone offset.
    Returns date_str unchanged if the format is unrecognised.
    """
    m = re.match(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2})(.*)", date_str)
    if not m:
        return date_str
    return f"{datetime.now().strftime('%Y-%m-%d')}{m.group(1)}{m.group(2)}"


def _shift_date_10y(date_str: str) -> str:
    """Shift a cXML ISO 8601 date string's year +10, preserving month/day/time/tz.
    Handles Feb 29 → Feb 28 when the target year is not a leap year.
    Returns date_str unchanged if the format is unrecognised.
    """
    m = re.match(r"^(\d{4})(-\d{2})(-\d{2})(T\d{2}:\d{2}:\d{2})(.*)", date_str)
    if not m:
        return date_str
    year, month, day = int(m.group(1)), m.group(2), m.group(3)
    time_part, tz_part = m.group(4), m.group(5)
    new_year = year + 10
    if month == "-02" and day == "-29":
        is_leap = (new_year % 4 == 0 and new_year % 100 != 0) or (new_year % 400 == 0)
        if not is_leap:
            day = "-28"
    return f"{new_year}{month}{day}{time_part}{tz_part}"


# ---------------------------------------------------------------------------
# REGION DETECTION
# ---------------------------------------------------------------------------

def _resolve_profile(country_code: str, region: str) -> dict[str, str]:
    """Return the country profile for *country_code*, falling back to the region default."""
    if country_code in COUNTRY_PROFILES:
        return COUNTRY_PROFILES[country_code]
    default_country = REGION_DEFAULTS.get(region, REGION_DEFAULTS[DEFAULT_REGION])
    return COUNTRY_PROFILES[default_country]


def detect_country(root: lxml_ET._Element) -> tuple[str, str, str]:
    """Detect country and region from signals within the parsed cXML tree.

    Detection priority:
      1. ``isoCountryCode`` attribute — majority-vote across all ``<Country>`` elements.
      2. ``currency`` attribute on any ``<Money>`` element.
      3. Text content of ``<Country>`` elements matched case-insensitively.
      4. Falls back to DEFAULT_REGION / AU.

    Returns:
        (country_code, region, detection_method_description)
    """
    country_els: list[lxml_ET._Element] = []
    money_els: list[lxml_ET._Element] = []
    for el in root.iter():
        local = lxml_ET.QName(el.tag).localname
        if local == "Country":
            country_els.append(el)
        elif local == "Money":
            money_els.append(el)

    # 1. isoCountryCode — majority-vote across all Country elements
    code_counts: dict[str, int] = {}
    unmapped_codes: list[str] = []
    for el in country_els:
        code = el.get("isoCountryCode", "").upper()
        if not code:
            continue
        if code in ISO_COUNTRY_TO_REGION:
            code_counts[code] = code_counts.get(code, 0) + 1
        else:
            unmapped_codes.append(code)

    if code_counts:
        winner = max(code_counts, key=code_counts.get)
        region = ISO_COUNTRY_TO_REGION[winner]
        method = f"isoCountryCode='{winner}'"
        if len(code_counts) > 1:
            method += f" (majority of {sum(code_counts.values())})"
        if unmapped_codes:
            method += f" [unmapped: {', '.join(sorted(set(unmapped_codes)))}]"
        return winner, region, method

    # 2. currency attribute on <Money>
    for el in money_els:
        currency = el.get("currency", "").upper()
        if currency in CURRENCY_TO_COUNTRY:
            region, country = CURRENCY_TO_COUNTRY[currency]
            return country, region, f"currency='{currency}'"

    # 3. Country text content
    for el in country_els:
        if el.text:
            name = el.text.strip().lower()
            if name in COUNTRY_NAME_TO_COUNTRY:
                region, country = COUNTRY_NAME_TO_COUNTRY[name]
                return country, region, f"country name='{el.text.strip()}'"

    # 4. Default fallback
    fallback_method = "fallback default"
    if unmapped_codes:
        fallback_method += f" [unmapped isoCountryCode: {', '.join(sorted(set(unmapped_codes)))}]"
    default_country = REGION_DEFAULTS[DEFAULT_REGION]
    return default_country, DEFAULT_REGION, fallback_method


# ---------------------------------------------------------------------------
# VALIDATION
# ---------------------------------------------------------------------------

def _detect_order_request_subtype(request_el: lxml_ET._Element) -> DocumentMeta:
    """Classify an OrderRequest based on header attributes (type, orderVersion, orderType)
    and element-tree content (Service PO detection via SpendDetail/ServicePeriod).
    """
    orh = request_el.find(".//OrderRequestHeader")
    if orh is None:
        return DocumentMeta(base_type="OrderRequest")

    po_type = orh.get("type", "new").lower()
    order_version = orh.get("orderVersion", "1")
    order_type = orh.get("orderType", "regular")
    has_doc_ref = orh.find("DocumentReference") is not None
    has_service_period = (
        request_el.find(".//SpendDetail/Extrinsic[@name='ServicePeriod']") is not None
    )

    if po_type == "delete":
        sub_type = "Cancel"
    elif po_type == "update":
        sub_type = "Change"
    else:
        try:
            is_higher_version = int(order_version) > 1
        except (ValueError, TypeError):
            is_higher_version = False
        sub_type = "Change" if is_higher_version else "New"

    return DocumentMeta(
        base_type="OrderRequest",
        sub_type=sub_type,
        order_version=order_version,
        order_type=order_type,
        has_document_reference=has_doc_ref,
        is_service_po=has_service_period,
    )


def validate_cxml_file(xml_content: str) -> tuple[bool, str, DocumentMeta | None]:
    """Validate an uploaded file as a well-formed, structurally correct cXML document.

    Uses defusedxml as a security gate, then lxml (via the hardened parser) for
    structural inspection.

    Returns:
        (is_valid, message, document_meta)
        document_meta is None when is_valid is False.
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
    doc_meta = DocumentMeta(base_type="Unknown")
    request = root.find("Request")
    response = root.find("Response")

    if request is not None:
        if request.find(".//OrderRequest") is not None:
            doc_meta = _detect_order_request_subtype(request)
        elif request.find(".//ConfirmationRequest") is not None:
            doc_meta = DocumentMeta(base_type="OrderConfirmation")
        elif request.find(".//ShipNoticeRequest") is not None:
            doc_meta = DocumentMeta(base_type="ShipNotice")
        elif request.find(".//InvoiceDetailRequest") is not None:
            doc_meta = DocumentMeta(base_type="Invoice")
        else:
            doc_meta = DocumentMeta(base_type="Request (Other)")
    elif response is not None:
        doc_meta = DocumentMeta(base_type="Response")

    return True, "Valid cXML document.", doc_meta


# ---------------------------------------------------------------------------
# ANONYMIZATION
# ---------------------------------------------------------------------------

def apply_header_template(root: lxml_ET._Element, doc_meta: DocumentMeta | None = None) -> list[dict]:
    """Overwrite cXML envelope attributes and the Header / OrderRequestHeader
    with sanitised placeholder values.

    Returns a list of dicts with keys: field, original, anonymized.
    """
    log: list[dict] = []

    for attr, new_val in [
        ("payloadID", "#PAYLOADID#"),
        ("timestamp", "2026-01-01T14:53:00-07:00"),  # intentionally static — anonymized docs use a fixed date
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
            preserve_po_attrs = (
                doc_meta is not None
                and doc_meta.base_type == "OrderRequest"
                and doc_meta.sub_type in ("Change", "Cancel")
            )

            current_order_type = (
                doc_meta.order_type
                if doc_meta is not None and doc_meta.order_type
                else orh.get("orderType", "regular")
            )

            orh_replacements: list[tuple[str, str]] = [
                ("orderDate", "#DATETIME#"),
                ("orderID", "#DOCUMENTID#"),
                ("orderType", current_order_type),
            ]

            if preserve_po_attrs:
                current_version = orh.get("orderVersion", "1")
                current_type = orh.get("type", "new")
                orh_replacements.append(("orderVersion", current_version))
                orh_replacements.append(("type", current_type))
            else:
                orh_replacements.append(("orderVersion", "1"))
                orh_replacements.append(("type", "new"))

            for attr, new_val in orh_replacements:
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

            if current_order_type != "regular":
                log.append({
                    "field": "<OrderRequestHeader orderType>",
                    "original": current_order_type,
                    "anonymized": f"(preserved — {current_order_type})",
                })

            if preserve_po_attrs:
                log.append({
                    "field": "<OrderRequestHeader orderVersion>",
                    "original": orh.get("orderVersion", "1"),
                    "anonymized": f"(preserved — {doc_meta.sub_type} PO)",
                })
                log.append({
                    "field": "<OrderRequestHeader type>",
                    "original": orh.get("type", "new"),
                    "anonymized": f"(preserved — {doc_meta.sub_type} PO)",
                })

            ot_attrs = _ORDER_TYPE_ATTRS.get(current_order_type, {})
            for attr_name, anon_placeholder in ot_attrs.items():
                old_val = orh.get(attr_name)
                if old_val is None:
                    continue
                if anon_placeholder is not None:
                    orh.set(attr_name, anon_placeholder)
                    log.append({
                        "field": f"<OrderRequestHeader {attr_name}>",
                        "original": old_val,
                        "anonymized": anon_placeholder,
                    })
                else:
                    log.append({
                        "field": f"<OrderRequestHeader {attr_name}>",
                        "original": old_val,
                        "anonymized": f"(preserved — {current_order_type})",
                    })

            doc_ref = orh.find("DocumentReference")
            if doc_ref is not None:
                if preserve_po_attrs:
                    old_ref_id = doc_ref.get("payloadID", "")
                    doc_ref.set("payloadID", "#PREV_PAYLOADID#")
                    log.append({
                        "field": "<DocumentReference payloadID>",
                        "original": old_ref_id or "(empty)",
                        "anonymized": "#PREV_PAYLOADID#",
                    })
                else:
                    orh.remove(doc_ref)
                    log.append({
                        "field": "<DocumentReference>",
                        "original": "(element removed — unexpected on New PO)",
                        "anonymized": "(removed)",
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
            elif extrinsic_name == "ServicePeriod":
                # Structured extrinsic — contains a <Period> child element, not text.
                # Do NOT replace child.text; the <Period> dates are handled below via recursion.
                log.append({
                    "field": '<Extrinsic name="ServicePeriod">',
                    "original": "(structured — Period dates below)",
                    "anonymized": "(structure preserved — Period dates anonymized)",
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

        # Service period date anonymization — all <Period> elements in document.
        # startDate → today's run date (time/tz preserved); endDate → year +10.
        if local_tag == "Period":
            for attr, transform in [
                ("startDate", _replace_date_today),
                ("endDate", _shift_date_10y),
            ]:
                old_val = child.get(attr)
                if old_val is not None:
                    new_val = transform(old_val)
                    child.set(attr, new_val)
                    log.append({
                        "field": f"<Period {attr}>",
                        "original": old_val,
                        "anonymized": new_val,
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
        # Skip OrderRequestHeader — its attributes are fully managed by apply_header_template
        if local_tag == "OrderRequestHeader":
            log.extend(anonymize_elements(child, profile))
            continue
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
    country_code: str | None = None,
    region_code: str | None = None,
    detection_method: str | None = None,
    doc_meta: DocumentMeta | None = None,
) -> tuple[str, list[dict], str, str, str]:
    """Parse, anonymize and serialise a cXML document.

    FIX #6 — accepts pre-detected (country_code, region_code, detection_method)
    so the caller can pass in results already computed during the upload display
    loop, avoiding a redundant third lxml parse per file.

    Returns:
        (anonymized_xml_string, substitution_log, country_code, region_code, detection_method)
    """
    # FIX #1 — use the hardened parser everywhere lxml touches user content
    root: lxml_ET._Element = lxml_ET.fromstring(xml_content.encode(), parser=_SAFE_PARSER)

    if country_code is None or region_code is None or detection_method is None:
        country_code, region_code, detection_method = detect_country(root)

    profile = _resolve_profile(country_code, region_code)
    active_profile: dict[str, str] = {**GENERIC_ANONYMIZATION_MAP, **profile}
    active_profile.pop("display_name", None)
    active_profile.pop("region", None)

    header_log = apply_header_template(root, doc_meta=doc_meta)
    element_log = anonymize_elements(root, active_profile)
    log = header_log + element_log

    output_bytes: bytes = lxml_ET.tostring(
        root,
        pretty_print=True,
        xml_declaration=True,
        encoding="utf-8",
    )
    output_string = _insert_doctype(output_bytes.decode("utf-8"))

    return output_string, log, country_code, region_code, detection_method


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
    """Display XML content with syntax highlighting in a height-constrained container."""
    st.code(xml_text, language="xml", line_numbers=True, height=height_px)


# ---------------------------------------------------------------------------
# HELPER: render the processing summary as a scrollable, copyable table
# ---------------------------------------------------------------------------

def _render_summary_table(log: list[dict], filename: str, height_px: int = 400) -> None:
    """Render the substitution log as a native Streamlit dataframe with a TSV download."""
    unique_log = _deduplicate_log(log)

    if not unique_log:
        st.info("No substitutions were recorded for this file.")
        return

    data = [
        {
            "#": idx,
            "Field": entry["field"],
            "Original Value": entry["original"] or "(empty)",
            "Anonymized Value": entry["anonymized"],
        }
        for idx, entry in enumerate(unique_log, 1)
    ]
    st.dataframe(data, use_container_width=True, height=height_px, hide_index=True)

    tsv_lines = ["#\tField\tOriginal Value\tAnonymized Value"]
    for idx, entry in enumerate(unique_log, 1):
        tsv_lines.append(f"{idx}\t{entry['field']}\t{entry['original']}\t{entry['anonymized']}")
    tsv_text = "\n".join(tsv_lines)

    st.download_button(
        label="📋 Download as TSV (paste into Excel / Sheets)",
        data=tsv_text,
        file_name=f"substitution_summary_{filename}.tsv",
        mime="text/tab-separated-values",
        key=f"tsv_{_stable_id(filename)}",
    )
    st.caption(f"{len(unique_log)} unique substitution(s)")


# ---------------------------------------------------------------------------
# THEME  — CSS custom-property injection
# ---------------------------------------------------------------------------

def _inject_theme_css(dark: bool) -> None:
    """Inject a single <style> block that sets all --tc-* CSS variables
    and (in dark mode) overrides the Streamlit chrome so the entire app
    is visually consistent across both modes.
    """
    if dark:
        vars_css = """
        :root {
            --tc-bg-valid:              #0e4429;
            --tc-bg-invalid:            #4a1a1a;
            --tc-bg-warning:            #1a1a2e;
            --tc-bg-service:            #0d2444;
            --tc-border:                #444444;
            --tc-border-valid:          #238636;
            --tc-border-invalid:        #d73a49;
            --tc-text-secondary:        #8b949e;
            --tc-text-valid:            #3fb950;
            --tc-text-invalid:          #f85149;
            --tc-text-warning:          #faad14;
            --tc-text-service:          #79c0ff;
        }
        """
        chrome_css = """
        /* ---- Streamlit chrome: dark overrides ---- */
        .stApp,
        [data-testid="stAppViewContainer"] {
            background-color: #0e1117 !important;
        }
        [data-testid="stSidebar"],
        [data-testid="stSidebar"] > div:first-child {
            background-color: #161b22 !important;
        }
        [data-testid="stHeader"] {
            background-color: #161b22 !important;
            border-bottom: 1px solid #30363d !important;
        }
        /* Headings */
        .stApp h1, .stApp h2, .stApp h3,
        .stApp h4, .stApp h5, .stApp h6 {
            color: #e6edf3 !important;
        }
        /* Body text */
        [data-testid="stMarkdownContainer"] p,
        [data-testid="stMarkdownContainer"] li,
        [data-testid="stMarkdownContainer"] span:not([data-testid]),
        .stCaption, .stText {
            color: #c9d1d9 !important;
        }
        /* Sidebar text */
        [data-testid="stSidebar"] p,
        [data-testid="stSidebar"] li,
        [data-testid="stSidebar"] span,
        [data-testid="stSidebar"] label {
            color: #c9d1d9 !important;
        }
        /* Sidebar headers */
        [data-testid="stSidebar"] h1,
        [data-testid="stSidebar"] h2,
        [data-testid="stSidebar"] h3 {
            color: #e6edf3 !important;
        }
        /* Dividers */
        hr { border-color: #30363d !important; }
        /* Toggle & checkbox labels */
        .stCheckbox label, .stToggle label {
            color: #c9d1d9 !important;
        }
        /* Expander */
        [data-testid="stExpander"] summary {
            color: #c9d1d9 !important;
            background-color: #161b22 !important;
        }
        [data-testid="stExpander"] details {
            border-color: #30363d !important;
            background-color: #0e1117 !important;
        }
        /* File uploader */
        [data-testid="stFileUploader"] {
            background-color: #161b22 !important;
            border-color: #30363d !important;
        }
        [data-testid="stFileUploader"] label,
        [data-testid="stFileUploader"] span,
        [data-testid="stFileUploader"] p {
            color: #c9d1d9 !important;
        }
        /* Buttons */
        [data-testid="stButton"] button,
        [data-testid="stDownloadButton"] button {
            background-color: #21262d !important;
            border-color: #30363d !important;
            color: #c9d1d9 !important;
        }
        [data-testid="stButton"] button:hover,
        [data-testid="stDownloadButton"] button:hover {
            background-color: #30363d !important;
            border-color: #8b949e !important;
        }
        /* Alert / info / success / warning / error boxes */
        [data-testid="stAlert"] {
            background-color: #161b22 !important;
            border-color: #30363d !important;
        }
        [data-testid="stAlert"] p {
            color: #c9d1d9 !important;
        }
        /* Progress bar */
        [data-testid="stProgressBar"] > div > div {
            background-color: #1f6feb !important;
        }
        /* Checkbox */
        .stCheckbox span[data-baseweb="checkbox"] {
            background-color: #21262d !important;
        }
        /* Expander overflow */
        div[data-testid="stExpander"] details div[data-testid="stMarkdownContainer"] {
            max-height: 300px;
            overflow-y: auto;
        }
        """
    else:
        vars_css = """
        :root {
            --tc-bg-valid:              #dafbe1;
            --tc-bg-invalid:            #ffebe9;
            --tc-bg-warning:            #fff8c5;
            --tc-bg-service:            #ddf4ff;
            --tc-border:                #d0d7de;
            --tc-border-valid:          #2da44e;
            --tc-border-invalid:        #d1242f;
            --tc-text-secondary:        #636c76;
            --tc-text-valid:            #1a7f37;
            --tc-text-invalid:          #cf222e;
            --tc-text-warning:          #9a6700;
            --tc-text-service:          #0550ae;
        }
        """
        # Light mode: Streamlit's own light theme (config.toml base=light) is correct;
        # only add the expander overflow fix.
        chrome_css = """
        div[data-testid="stExpander"] details div[data-testid="stMarkdownContainer"] {
            max-height: 300px;
            overflow-y: auto;
        }
        """

    st.markdown(
        f"<style>{vars_css}{chrome_css}</style>",
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

if "clear_trigger" not in st.session_state:
    st.session_state.clear_trigger = 0
if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = True

# Inject theme CSS variables + Streamlit chrome overrides.
# Must be called after session state is initialised and before any widget.
_inject_theme_css(st.session_state.dark_mode)

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

    st.header("🌍 Auto Country & Region Detection")
    st.markdown(
        """
        Country and region are detected automatically using
        (in priority order):

        1. `isoCountryCode` on `<Country>` elements (majority-vote)
        2. `currency` on `<Money>` elements
        3. `<Country>` text content

        **Regions:** APAC, NAMAR, EMEA, Japan, LATAM

        Each detected country gets locale-accurate anonymized values
        (postal code, currency, phone format). Countries without a
        dedicated profile fall back to their region default.

        Falls back to **Australia (APAC)** if no signal is found.
        """
    )
    st.divider()

    st.header("📋 Document Types")
    st.markdown(
        """
        | Type | Detection |
        |------|-----------|
        | **New PO** | `type="new"` (default) |
        | **Change PO** | `type="update"` or `orderVersion` > 1 |
        | **Cancel PO** | `type="delete"` |
        | **Order Confirmation** | `<ConfirmationRequest>` |
        | **Ship Notice** | `<ShipNoticeRequest>` |
        | **Invoice** | `<InvoiceDetailRequest>` |

        Change and Cancel POs preserve the original `orderVersion`,
        `type`, and `<DocumentReference>` during anonymization.
        """
    )
    st.divider()

    st.header("📦 Order Types")
    st.markdown(
        """
        The `orderType` attribute is detected and preserved:

        | Order Type | Related Attributes |
        |------------|--------------------|
        | **regular** | *(default — no extra attrs)* |
        | **release** | `agreementID`, `agreementPayloadID` |
        | **blanket** | `releaseRequired`, `parentAgreementID`, `parentAgreementPayloadID`, `effectiveDate`, `expirationDate` |
        | **stockTransport** | *(no extra attrs)* |
        | **stockTransportRelease** | *(no extra attrs)* |

        ID/payload attributes are anonymized to placeholders;
        flags and dates are preserved as-is.
        """
    )
    st.divider()

    st.header("🔄 Reset")
    if st.button("🗑️ Clear All Files", use_container_width=True):
        st.session_state.clear_trigger += 1
        st.rerun()

    st.divider()

    st.header("🎨 Appearance")
    new_dark = st.toggle(
        "🌙 Dark Mode",
        value=st.session_state.dark_mode,
        key="dark_mode_toggle",
        help="Switch between dark and light themes.",
    )
    if new_dark != st.session_state.dark_mode:
        st.session_state.dark_mode = new_dark
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
        is_valid, validation_message, doc_meta = False, f"File is not valid UTF-8: {exc}", None
        file_content = ""
    else:
        is_valid, validation_message, doc_meta = validate_cxml_file(file_content)

    # FIX #6 — detect country once here and store it in file_configs so
    # process_cxml_content does not need to parse a third time per file.
    detected_country = REGION_DEFAULTS[DEFAULT_REGION]
    detected_region = DEFAULT_REGION
    detected_by = "fallback default"
    detected_profile = _resolve_profile(detected_country, detected_region)
    detected_display_label = detected_profile["display_name"]

    if is_valid:
        try:
            root_preview = lxml_ET.fromstring(file_content.encode(), parser=_SAFE_PARSER)
            detected_country, detected_region, detected_by = detect_country(root_preview)
            detected_profile = _resolve_profile(detected_country, detected_region)
            detected_display_label = detected_profile["display_name"]
        except Exception as e:
            st.warning(
                f"Could not detect country for **{_html.escape(uploaded_file.name)}** "
                f"— defaulting to {detected_display_label}. ({type(e).__name__}: {e})"
            )

    with st.container():
        col1, col2, col3 = st.columns([2, 2, 1])

        # FIX #2 — escape filename before inserting into unsafe_allow_html blocks
        safe_display_name = _html.escape(uploaded_file.name)

        with col1:
            file_size = len(raw) / 1024
            st.markdown(
                f"**📄 {safe_display_name}**  \n"
                f"<span style='color:var(--tc-text-secondary); font-size:0.85rem;'>"
                f"Size: {file_size:.1f} KB</span>",
                unsafe_allow_html=True,
            )

        with col2:
            if is_valid:
                safe_region_label = _html.escape(detected_display_label)
                safe_detected_by = _html.escape(detected_by)
                st.markdown(
                    f"🌍 **{safe_region_label}**  \n"
                    f"<span style='color:var(--tc-text-secondary); font-size:0.85rem;'>"
                    f"Detected via: {safe_detected_by}</span>",
                    unsafe_allow_html=True,
                )
            else:
                st.empty()

        with col3:
            if is_valid:
                safe_doc_label = _html.escape(doc_meta.display_label if doc_meta else "")

                if doc_meta and doc_meta.is_change_po:
                    badge_bg = "var(--tc-bg-warning)"
                    badge_border = "#d29922"
                    badge_text_color = "var(--tc-text-warning)"
                    badge_icon = "🔄"
                elif doc_meta and doc_meta.is_cancel_po:
                    badge_bg = "var(--tc-bg-invalid)"
                    badge_border = "var(--tc-border-invalid)"
                    badge_text_color = "var(--tc-text-invalid)"
                    badge_icon = "🚫"
                elif doc_meta and doc_meta.is_service_po:
                    badge_bg = "var(--tc-bg-service)"
                    badge_border = "#0550ae"
                    badge_text_color = "var(--tc-text-service)"
                    badge_icon = "🔧"
                else:
                    badge_bg = "var(--tc-bg-valid)"
                    badge_border = "var(--tc-border-valid)"
                    badge_text_color = "var(--tc-text-valid)"
                    badge_icon = "✅"

                detail_line = ""
                detail_parts: list[str] = []
                if doc_meta and doc_meta.is_change_po and doc_meta.order_version:
                    detail_parts.append(f"v{_html.escape(doc_meta.order_version)}")
                if doc_meta and doc_meta.order_type_label:
                    detail_parts.append(_html.escape(doc_meta.order_type_label))
                if detail_parts:
                    detail_line = (
                        f"<br><span style='font-size:0.75rem;'>"
                        f"{' | '.join(detail_parts)}</span>"
                    )

                st.markdown(
                    f"<div style='"
                    f"background-color: {badge_bg};"
                    f"border: 1px solid {badge_border};"
                    f"border-radius: 6px;"
                    f"padding: 0.35rem 0.6rem;"
                    f"text-align: center;"
                    f"font-size: 0.85rem;"
                    f"color: {badge_text_color};"
                    f"line-height: 1.3;"
                    f"margin-top: 0.25rem;"
                    f"'>{badge_icon} {safe_doc_label}{detail_line}</div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    "<div style='"
                    "background-color: var(--tc-bg-invalid);"
                    "border: 1px solid var(--tc-border-invalid);"
                    "border-radius: 6px;"
                    "padding: 0.35rem 0.6rem;"
                    "text-align: center;"
                    "font-size: 0.85rem;"
                    "color: var(--tc-text-invalid);"
                    "line-height: 1.3;"
                    "margin-top: 0.25rem;"
                    "'>❌ Invalid</div>",
                    unsafe_allow_html=True,
                )
                validation_errors.append(
                    f"**{safe_display_name}:** {_html.escape(validation_message)}"
                )

        with st.expander(f"👁️ Preview source — {uploaded_file.name}"):
            _render_scrollable_xml(file_content, height_px=300)

        if is_valid:
            file_configs.append({
                "file": uploaded_file,
                "doc_meta": doc_meta,
                # FIX #6 — carry pre-detected country/region through to avoid re-parsing
                "country_code": detected_country,
                "region_code": detected_region,
                "detection_method": detected_by,
                "xml_content": file_content,
            })

        st.divider()

if validation_errors:
    with st.expander("⚠️ Validation Errors — click to expand", expanded=True):
        error_html = "".join(
            f"<p style='color:var(--tc-text-warning); margin:0.3rem 0;'>⚠️ {err}</p>"
            for err in validation_errors
        )
        st.markdown(
            f"""
            <div style="
                max-height: 200px;
                overflow-y: auto;
                border: 1px solid var(--tc-border);
                border-radius: 6px;
                padding: 0.75rem;
                background-color: var(--tc-bg-warning);
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

        # FIX #6 — pass pre-detected country/region so process_cxml_content skips re-detection
        anonymized_content, log, country_code, region_code, detection_method = process_cxml_content(
            xml_content,
            country_code=config["country_code"],
            region_code=config["region_code"],
            detection_method=config["detection_method"],
            doc_meta=config["doc_meta"],
        )
        profile = _resolve_profile(country_code, region_code)
        region_display = profile["display_name"]

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
            "doc_meta": config["doc_meta"],
            "processed_at": datetime.now().isoformat(timespec="seconds"),
            "dry_run": dry_run,
        }
    except ValueError as e:
        errors.append(f"❌ **{_html.escape(file.name)}** — Validation error: {e}")
    except Exception as e:
        _log.exception("Unexpected error processing %s", file.name)
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
        col1, col2 = st.columns([3, 1])
        with col1:
            with st.expander(f"👁️ Preview anonymized — {filename}"):
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
st.caption("Auto-detected country/region, document type, timestamp, and every field substitution.")

for filename, info in processing_logs.items():
    log = info["log"]
    region = info["region"]
    detection_method = info["detection_method"]
    processed_at = info["processed_at"]
    is_dry_run = info["dry_run"]
    meta = info.get("doc_meta")
    dry_run_badge = " 🔍 Dry-run" if is_dry_run else ""

    unique_count = len(_deduplicate_log(log))

    with st.expander(
        f"🔍 {filename} — {region} — {unique_count} substitution(s){dry_run_badge}"
    ):
        caption_parts = [f"Processed at: {processed_at}"]
        if meta:
            caption_parts.append(f"Type: {meta.display_label}")
            if meta.order_type_label:
                caption_parts.append(f"Order: {meta.order_type_label}")
        caption_parts.append(f"Detected via: {detection_method}")
        st.caption(" | ".join(caption_parts))
        _render_summary_table(log, filename, height_px=700)

# --- Footer ---
st.divider()
st.markdown(
    "<p style='text-align: center; color: var(--tc-text-secondary);'>cXML Anonymizer Tool | Test Central Preparation</p>",
    unsafe_allow_html=True,
)