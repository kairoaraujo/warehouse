import pretend

from tuf.api.metadata import Key
from zope.interface.verify import verifyClass

from warehouse.tuf import services
from warehouse.tuf.interfaces import IKeyService
from warehouse.tuf.services import LocalKeyService


class TestLocalLocalKeyService:
    def test_verify_service(self):
        assert verifyClass(IKeyService, LocalKeyService)

    def test_create_service(self):
        request = pretend.stub(
            registry=pretend.stub(settings={"tuf.key.path": "/tuf/key/path/"})
        )
        service = LocalKeyService.create_service(None, request)
        assert service._key_path == "/tuf/key/path/"

    def test_basic_init(self, db_request):
        service = LocalKeyService("/opt/warehouse/src/dev/tufkeys", db_request)
        assert service._key_path == "/opt/warehouse/src/dev/tufkeys"

    def test_pubkeys_for_role(self, monkeypatch, db_request):
        service = LocalKeyService("/opt/warehouse/src/dev/tufkeys", db_request)

        expected_priv_key_dict = {
            "keytype": "ed25519",
            "scheme": "ed25519",
            "keyval": {
                "public": "720a9a588deefd533c36da9b071f7c7b4d08984e87bfc5a18f34618e438434c7"
            },
            "keyid": "2de4eb9afe9fb7307f1dd0869a7aec2235d3418bd63f4214d3ba7d23b516f23e",
            "keyid_hash_algorithms": ["sha256", "sha512"],
        }

        monkeypatch.setattr(
            "warehouse.tuf.services.import_ed25519_publickey_from_file",
            lambda *a, **kw: expected_priv_key_dict,
        )

        root_keyid = service.pubkeys_for_role("root")

        assert isinstance(root_keyid, Key)
        assert root_keyid.to_dict().get("keyid") == expected_priv_key_dict.get("keyid")
