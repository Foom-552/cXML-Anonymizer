# cXML Anonymizer Tool

A Streamlit web application for securely anonymizing cXML transactional documents before submission to **Test Central** via the Managed Gateway.

---

## What It Does

Upload one or more cXML documents (`.xml` or `.txt`) and replace sensitive data — names, email addresses, tax IDs, phone numbers, order references, addresses, and more — with safe, realistic placeholder values, while preserving the document structure and format required for Test Central setup.

---

## Features

- **Auto region detection** — reads `isoCountryCode`, `currency`, and `<Country>` content to automatically apply the correct locale format (AU, NAMAR, EMEA, Japan)
- **PO type awareness** — detects New, Change, and Cancel purchase orders and preserves their semantic attributes during anonymization
- **Smart Extrinsic handling** — anonymizes Extrinsic field values based on their `name` attribute; system/classification codes are preserved unchanged
- **Document type detection** — identifies OrderRequest, OrderConfirmation, ShipNotice, Invoice, and other cXML document types with colour-coded badges
- **Dry-run mode** — preview exactly what would be anonymized before producing output files
- **Batch processing** — upload and process up to 50 files at once (10 MB each, 50 MB total) with ZIP download
- **Processing summary** — full audit trail of every substitution made per file, with TSV export
- **Dark / light mode** — toggle between themes via the sidebar
- **Security hardened** — uses `defusedxml` to prevent XML bomb / entity expansion attacks; hardened lxml parser with no network access, no entity resolution, and no DTD loading

---

## Supported Document Types

| Type | Detection | Badge |
|------|-----------|-------|
| **New PO** | `type="new"` or default | Green |
| **Change PO** | `type="update"` or `orderVersion` > 1, with `<DocumentReference>` | Amber |
| **Cancel PO** | `type="delete"` | Red |
| **Order Confirmation** | `<ConfirmationRequest>` element | Green |
| **Ship Notice** | `<ShipNoticeRequest>` element | Green |
| **Invoice** | `<InvoiceDetailRequest>` element | Green |

### Change and Cancel PO Handling

When a Change or Cancel purchase order is detected, the anonymizer preserves the following fields instead of overwriting them with defaults:

- **`orderVersion`** — kept as-is (e.g. `"2"`, `"3"`) instead of being reset to `"1"`
- **`type`** — kept as `"update"` or `"delete"` instead of being reset to `"new"`
- **`<DocumentReference payloadID>`** — the element is preserved and the payload ID is anonymized to `#PREV_PAYLOADID#`

### Order Types (`orderType`)

The `orderType` attribute is detected and preserved for all purchase orders. Related attributes are handled per order type:

| Order Type | Description | Related Attributes |
|------------|-------------|--------------------|
| `regular` | Standard purchase order (default) | — |
| `release` | Release against a master agreement or blanket PO | `agreementID` (anonymized), `agreementPayloadID` (anonymized) |
| `blanket` | Blanket purchase order | `releaseRequired` (preserved), `parentAgreementID` (anonymized), `parentAgreementPayloadID` (anonymized), `effectiveDate` (preserved), `expirationDate` (preserved) |
| `stockTransport` | Stock transport order | — |
| `stockTransportRelease` | Stock transport scheduling agreement release | — |

ID and payload ID attributes are anonymized to placeholders (e.g. `#AGREEMENTID#`, `#PARENT_AGREEMENT_PAYLOADID#`). Flags (`releaseRequired`) and dates (`effectiveDate`, `expirationDate`) are preserved as-is.

All other fields (names, addresses, identifiers, etc.) are still fully anonymized as normal.

---

## Supported Regions & Countries

The anonymizer detects the country from `<Country isoCountryCode>` (majority-vote across all elements), `<Money currency>`, or `<Country>` text content. Each detected country gets locale-accurate anonymized values. Countries without a dedicated profile fall back to their region's default.

| Region | Default | Countries with Dedicated Profiles |
|--------|---------|-----------------------------------|
| **APAC** | Australia (AU) | AU, NZ, IN, CN, SG, KR, TH, ID, PH, MY |
| **NAMAR** | United States (US) | US, CA, MX |
| **EMEA** | Germany (DE) | DE, GB, FR, NL, CH, SE, AE, SA, ZA, IL, TR |
| **Japan** | Japan (JP) | JP |
| **LATAM** | Brazil (BR) | BR, AR, CO, CL |

Additional countries are mapped to regions (e.g. VN → APAC, PL → EMEA, PE → LATAM) and use the region default profile. Falls back to Australia (APAC) if no signal is found.

Detection features:
- **Majority-vote**: when multiple `<Country>` elements have different codes, the most common one wins
- **Unmapped code visibility**: unmapped ISO codes are reported in the detection method so you can see what fell through

---

## What Gets Anonymized

- **PII** — names, email addresses, phone numbers, contact details
- **Tax & registration** — VAT IDs, ABNs, GST numbers, tax IDs
- **Business identifiers** — supplier/buyer IDs, vendor IDs, customer IDs
- **Procurement references** — order IDs, invoice IDs, contract IDs, requisition numbers
- **Addresses** — street, city, state, postal code, country (replaced with region-appropriate values)
- **Financial** — monetary amounts, approval data
- **Organisation** — cost centres, GL accounts, WBS elements, profit centres, company codes
- **System** — network IDs, ERP system IDs, instance IDs
- **Free text** — comments, notes, descriptions
- **Header & envelope** — payload IDs, timestamps, credentials, user agents

### What Gets Preserved

- XML structure and namespaces
- System/classification codes listed in `PRESERVE_EXTRINSIC_NAMES`
- Document type and format validity
- Change/Cancel PO semantics (`orderVersion`, `type`, `<DocumentReference>`)
- Order type (`orderType`) and related non-sensitive attributes (`releaseRequired`, `effectiveDate`, `expirationDate`)

---

## Privacy

Uploaded files are processed entirely in-memory within the user's session and are never stored, logged, or transmitted to any third party. No data is retained after the session ends.

---

## Local Setup

**Requirements:** Python 3.10+

```bash
# Clone the repository
git clone https://github.com/your-username/cxml-anonymizer.git
cd cxml-anonymizer

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run cxml_anonymizer.py
```

The app will open at `http://localhost:8501`.

---

## Deployment

This app is designed to deploy on [Streamlit Community Cloud](https://share.streamlit.io):

1. Fork or push this repository to GitHub
2. Go to [share.streamlit.io](https://share.streamlit.io) and sign in with GitHub
3. Click **New app** → select your repository → set main file to `cxml_anonymizer.py`
4. Click **Deploy**

Any `git push` to the repository will automatically redeploy the app.

---

## Extending the Tool

### Adding New Extrinsic Mappings

Edit the two constants in `cxml_anonymizer.py`:

- **`EXTRINSIC_ANONYMIZATION_MAP`** — add `"fieldName": "Anonymized Placeholder"` to anonymize a field
- **`PRESERVE_EXTRINSIC_NAMES`** — add `"fieldName"` to keep a field's value unchanged

### Adding New Document Types

Document type detection uses the `DocumentMeta` dataclass. To add a new type:

1. Add detection logic in `validate_cxml_file()` (look for the element in the `<Request>` body)
2. For sub-types (like Change/Cancel POs), create a `_detect_<type>_subtype()` helper
3. Add any preservation rules in `apply_header_template()` if the new type has attributes that should not be overwritten

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `streamlit` | Web UI framework |
| `lxml` | Namespace-aware XML parsing and serialisation |
| `defusedxml` | Security gate against malicious XML inputs |
