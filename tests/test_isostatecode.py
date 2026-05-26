"""Tests for isoStateCode attribute handling in anonymize_elements()."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from lxml import etree
from cxml_anonymizer import anonymize_elements, COUNTRY_PROFILES


def _make_address(state_text: str, iso_state_code: str | None = None) -> etree._Element:
    """Build a minimal <PostalAddress> element with a <State> child."""
    addr = etree.Element("PostalAddress")
    state = etree.SubElement(addr, "State")
    state.text = state_text
    if iso_state_code is not None:
        state.set("isoStateCode", iso_state_code)
    return addr


class TestIsoStateCodeAttribute:
    """isoStateCode attribute is updated/added to match the profile value."""

    def test_updates_existing_isostatecode(self):
        """Existing isoStateCode is replaced with the profile value."""
        profile = COUNTRY_PROFILES["US"]
        addr = _make_address("New York", iso_state_code="US-NY")

        anonymize_elements(addr, profile)

        state_el = addr.find("State")
        assert state_el.get("isoStateCode") == "US-CA"

    def test_adds_isostatecode_when_absent(self):
        """isoStateCode is added even when the original element had none."""
        profile = COUNTRY_PROFILES["US"]
        addr = _make_address("California")  # no isoStateCode attribute

        anonymize_elements(addr, profile)

        state_el = addr.find("State")
        assert state_el.get("isoStateCode") == "US-CA"

    def test_state_text_still_anonymized(self):
        """<State> text is still replaced with the profile value (regression guard)."""
        profile = COUNTRY_PROFILES["US"]
        addr = _make_address("New York", iso_state_code="US-NY")

        anonymize_elements(addr, profile)

        state_el = addr.find("State")
        assert state_el.text == "CA"

    def test_log_contains_isostatecode_entry(self):
        """Audit log includes a <State isoStateCode> entry with correct original/anonymized values."""
        profile = COUNTRY_PROFILES["US"]
        addr = _make_address("New York", iso_state_code="US-NY")

        log = anonymize_elements(addr, profile)

        entry = next((e for e in log if e["field"] == "<State isoStateCode>"), None)
        assert entry is not None, "<State isoStateCode> entry missing from log"
        assert entry["original"] == "US-NY"
        assert entry["anonymized"] == "US-CA"

    def test_log_no_entry_when_already_correct(self):
        """No log entry when isoStateCode already matches the profile."""
        profile = COUNTRY_PROFILES["US"]
        addr = _make_address("California", iso_state_code="US-CA")

        log = anonymize_elements(addr, profile)

        # This test enforces that isoStateCode must be implemented as a special-case
        # block with an old != new guard (like <Country isoCountryCode> at ~line 1366),
        # NOT via the general attribute-substitution loop which logs unconditionally.
        fields = [entry["field"] for entry in log]
        assert "<State isoStateCode>" not in fields

    def test_all_profiles_have_isostatecode_key(self):
        """Every COUNTRY_PROFILES entry must define isoStateCode."""
        missing = [k for k, v in COUNTRY_PROFILES.items() if "isoStateCode" not in v]
        assert missing == [], f"Profiles missing isoStateCode: {missing}"

    @pytest.mark.parametrize("country_key,expected_code", [
        ("AU", "AU-WA"),
        ("NZ", "NZ-AUK"),
        ("IN", "IN-MH"),
        ("CN", "CN-SH"),
        ("SG", "SG-01"),
        ("KR", "KR-11"),
        ("TH", "TH-10"),
        ("ID", "ID-JK"),
        ("PH", "PH-NCR"),
        ("MY", "MY-14"),
        ("US", "US-CA"),
        ("CA", "CA-ON"),
        ("MX", "MX-CMX"),
        ("DE", "DE-BE"),
        ("GB", "GB-ENG"),
        ("FR", "FR-IDF"),
        ("NL", "NL-NH"),
        ("CH", "CH-ZH"),
        ("SE", "SE-AB"),
        ("AE", "AE-DU"),
        ("SA", "SA-01"),
        ("ZA", "ZA-GP"),
        ("IL", "IL-TA"),
        ("TR", "TR-34"),
        ("JP", "JP-13"),
        ("BR", "BR-SP"),
        ("AR", "AR-B"),
        ("CO", "CO-DC"),
        ("CL", "CL-RM"),
    ])
    def test_profile_isostatecode_value(self, country_key, expected_code):
        """Each profile's isoStateCode matches the expected ISO 3166-2 value."""
        assert COUNTRY_PROFILES[country_key]["isoStateCode"] == expected_code
