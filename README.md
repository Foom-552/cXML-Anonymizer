# 🔒 cXML Anonymizer Tool

A Streamlit web application for securely anonymizing cXML transactional documents before submission to **Test Central** via the Managed Gateway.

---

## What It Does

Uploads one or more cXML documents (`.xml` or `.txt`) and replaces sensitive data — names, email addresses, tax IDs, phone numbers, order references, addresses, and more — with safe, realistic placeholder values, while preserving the document structure and format required for Test Central setup.

---

## Features

- **Auto region detection** — reads `isoCountryCode`, `currency`, and `<Country>` content to automatically apply the correct locale format (AU, NAMAR, EMEA, Japan)
- **Smart Extrinsic handling** — anonymizes Extrinsic field values based on their `name` attribute; system/classification codes are preserved unchanged
- **Document type detection** — identifies OrderRequest, OrderConfirmation, ShipNotice, Invoice, and other cXML document types
- **Dry-run mode** — preview exactly what would be anonymized before producing output files
- **Batch processing** — upload and process multiple files at once with ZIP download
- **Processing summary** — full audit trail of every substitution made per file
- **Security hardened** — uses `defusedxml` to prevent XML bomb / entity expansion attacks

---

## Supported Regions

| Code | Region |
|------|--------|
| AU | Australia (default fallback) |
| NAMAR | North America |
| EMEA | Europe, Middle East & Africa |
| Japan | Japan |

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

## Adding New Extrinsic Mappings

To add anonymization rules for new `<Extrinsic>` field names, edit the two constants in `cxml_anonymizer.py`:

- **`EXTRINSIC_ANONYMIZATION_MAP`** — add `"fieldName": "Anonymized Placeholder"` to anonymize a field
- **`PRESERVE_EXTRINSIC_NAMES`** — add `"fieldName"` to keep a field's value unchanged

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `streamlit` | Web UI framework |
| `lxml` | Namespace-aware XML parsing and serialisation |
| `defusedxml` | Security gate against malicious XML inputs |
