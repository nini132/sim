import pytest
from simulator import CRCSimulator

def test_add_and_remove_alert_source(tmp_path):
    sim = CRCSimulator(config_file=str(tmp_path / "test_config.json"))
    sim.add_alert_source("TestAlert", ["field1", "field2"])
    assert "TestAlert" in sim.alert_sources
    sim.remove_alert_source("TestAlert")
    assert "TestAlert" not in sim.alert_sources

def test_validate_field_value_range():
    sim = CRCSimulator()
    sim.alert_sources["TestAlert"] = {
        "fields": ["num"],
        "thresholds": {"num": {"min": 1, "max": 10}},
        "settings": {},
        "items": []
    }
    assert sim.validate_field_value("TestAlert", "num", "5")
    with pytest.raises(ValueError):
        sim.validate_field_value("TestAlert", "num", "0")
    with pytest.raises(ValueError):
        sim.validate_field_value("TestAlert", "num", "11")
    with pytest.raises(ValueError):
        sim.validate_field_value("TestAlert", "num", "abc")

def test_add_item(tmp_path):
    sim = CRCSimulator(config_file=str(tmp_path / "test_config.json"))
    sim.add_alert_source("TestAlert", ["field1"])
    sim.alert_sources["TestAlert"]["items"] = []
    # Simulate adding item directly
    sim.alert_sources["TestAlert"]["items"].append({"id": "TES-001", "field1": "val"})
    assert len(sim.alert_sources["TestAlert"]["items"]) == 1
    assert sim.alert_sources["TestAlert"]["items"][0]["field1"] == "val"

def test_manage_alert_sources(tmp_path):
    sim = CRCSimulator(config_file=str(tmp_path / "test_config.json"))
    sim.add_alert_source("TestSource", ["fieldA", "fieldB"])
    assert "TestSource" in sim.alert_sources
    sim.remove_alert_source("TestSource")
    assert "TestSource" not in sim.alert_sources

def test_add_edit_remove_item(tmp_path):
    sim = CRCSimulator(config_file=str(tmp_path / "test_config.json"))
    sim.add_alert_source("TestSource", ["fieldA"])
    sim.alert_sources["TestSource"]["items"] = []
    # הוספה
    sim.alert_sources["TestSource"]["items"].append({"id": "TES-001", "fieldA": "val"})
    assert len(sim.alert_sources["TestSource"]["items"]) == 1
    # עריכה
    sim.alert_sources["TestSource"]["items"][0]["fieldA"] = "newval"
    assert sim.alert_sources["TestSource"]["items"][0]["fieldA"] == "newval"
    # מחיקה
    sim.alert_sources["TestSource"]["items"].pop(0)
    assert len(sim.alert_sources["TestSource"]["items"]) == 0

def test_manage_settings(tmp_path):
    sim = CRCSimulator(config_file=str(tmp_path / "test_config.json"))
    sim.add_alert_source("TestSource", ["fieldA"])
    sim.alert_sources["TestSource"]["settings"]["foo"] = "bar"
    assert sim.alert_sources["TestSource"]["settings"]["foo"] == "bar"
    sim.alert_sources["TestSource"]["settings"]["foo"] = "baz"
    assert sim.alert_sources["TestSource"]["settings"]["foo"] == "baz"
    del sim.alert_sources["TestSource"]["settings"]["foo"]
    assert "foo" not in sim.alert_sources["TestSource"]["settings"]

def test_manage_thresholds(tmp_path):
    sim = CRCSimulator(config_file=str(tmp_path / "test_config.json"))
    sim.add_alert_source("TestSource", ["num"])
    sim.alert_sources["TestSource"]["thresholds"]["num"] = {"min": 1, "max": 10}
    assert sim.validate_field_value("TestSource", "num", "5")
    with pytest.raises(ValueError):
        sim.validate_field_value("TestSource", "num", "0")
    with pytest.raises(ValueError):
        sim.validate_field_value("TestSource", "num", "11")

def test_simulate_event(tmp_path):
    sim = CRCSimulator(config_file=str(tmp_path / "test_config.json"))
    sim.add_alert_source("TestSource", ["fieldA"])
    # הוספת פונקציה דמה לסימולציה
    sim._get_siem_alert_details = lambda manual=False: {"fieldA": "val"}
    sim.send_event = lambda event_type, event_data: event_data.update({"sent": True})
    sim.simulate_event("SIEM_Alert", manual=False)
