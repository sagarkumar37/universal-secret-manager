import pytest

from usm.providers import ProviderError, make_provider


@pytest.fixture
def v():
    return make_provider({"provider": "memory", "memory": {"bundle_filter": "--",
                                                          "seed": {"stg--api": {"app__A": "1", "app__B": "2"}}}})


def test_keys_never_values(v):
    keys, ver = v.list_keys("stg--api")
    assert keys == ["app__A", "app__B"] and ver == "1"


def test_update_create_delete(v):
    assert v.set_key("stg--api", "app__A", "x", must_exist=True, expect_version="1") == "2"
    assert v.set_key("stg--api", "app__C", "y", must_exist=False, expect_version="2") == "3"
    with pytest.raises(ProviderError):
        v.set_key("stg--api", "app__C", "z", must_exist=False, expect_version=None)   # create existing
    with pytest.raises(ProviderError):
        v.set_key("stg--api", "app__Z", "z", must_exist=True, expect_version=None)    # update missing
    assert v.delete_key("stg--api", "app__B", expect_version="3") == "4"
    assert v.list_keys("stg--api")[0] == ["app__A", "app__C"]


def test_stale_version_refused(v):
    v.set_key("stg--api", "app__A", "x", must_exist=True, expect_version="1")
    with pytest.raises(ProviderError, match="changed meanwhile"):
        v.set_key("stg--api", "app__B", "y", must_exist=True, expect_version="1")


def test_same_value_and_empty_refused(v):
    with pytest.raises(ProviderError):
        v.set_key("stg--api", "app__A", "1", must_exist=True, expect_version=None)
    with pytest.raises(ProviderError):
        v.set_key("stg--api", "app__A", "", must_exist=True, expect_version=None)


def test_restore_and_diff(v):
    v.set_key("stg--api", "app__A", "x", must_exist=True, expect_version=None)       # v2: A changed
    v.set_key("stg--api", "app__N", "n", must_exist=False, expect_version=None)      # v3: N added
    assert v.key_diff("stg--api", "3") == (["app__N"], [], [])
    assert v.key_diff("stg--api", "2") == ([], [], ["app__A"])
    assert v.restore_version("stg--api", "1") == "4"
    assert v.list_keys("stg--api")[0] == ["app__A", "app__B"]


def test_destroy_old_version_only(v):
    v.set_key("stg--api", "app__A", "x", must_exist=True, expect_version=None)       # v2 = current
    with pytest.raises(ProviderError, match="current version"):
        v.destroy_version("stg--api", "2")
    v.destroy_version("stg--api", "1")
    assert [x.state for x in v.versions("stg--api")] == ["enabled", "destroyed"]
    with pytest.raises(ProviderError, match="already deleted"):
        v.destroy_version("stg--api", "1")
    with pytest.raises(ProviderError):
        v.restore_version("stg--api", "1")                                         # destroyed: unreadable
    with pytest.raises(ProviderError, match="not found"):
        v.destroy_version("stg--api", "9")
    assert v.list_keys("stg--api") == (["app__A", "app__B"], "2")                   # current untouched


def test_no_bundle_delete_in_interface(v):
    assert not any(n for n in dir(v) if "bundle" in n and ("delete" in n or "destroy" in n))


def test_unmanaged_bundle_refused(v):
    with pytest.raises(ProviderError):
        v.list_keys("not-managed")
