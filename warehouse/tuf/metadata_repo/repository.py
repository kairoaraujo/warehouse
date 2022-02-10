import os
import datetime
from dataclasses import dataclass
from securesystemslib.signer import SSlibSigner
from securesystemslib.exceptions import StorageError
from typing import Dict, List, Optional
from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Delegations,
    Key,
    Metadata,
    MetaFile,
    Role,
    Root,
    Snapshot,
    StorageBackendInterface,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer
from warehouse.tuf.constants import BIN_N_COUNT, SPEC_VERSION
from warehouse.config import Environment


@dataclass
class TUFRepositoryFiles:
    filename: str
    data: Metadata


class MetadataRepository:

    def __init__(self, storage_backend: StorageBackendInterface):
        self.storage_backend = storage_backend
        self._is_initialized: bool = self._check_is_initialized()

    @property
    def is_initialized(self) -> bool:
        return self._is_initialized

    def _check_is_initialized(self) -> None:
        try:
            if any(
                role for role in TOP_LEVEL_ROLE_NAMES if isinstance(self.load(role), Metadata)
            ):
                self._is_initialized = True
        except StorageError:
            pass


    def initialize(self, init_roles_payload: dict) -> List[TUFRepositoryFiles]:
        """
        Initialize the TUF repository from scratch, including a brand new root.
        """

        self._check_is_initialized()
        if self.is_initialized:
            raise FileExistsError("Metadata already exists in the Storage Service")

        roles: Dict[str, Metadata] = dict()
        public_keys: Dict[str, Key] = dict()
        expiration: Dict[str, Key] = dict()
        threshold: Dict[str, Key] = dict()

        for role in TOP_LEVEL_ROLE_NAMES:
            if role not in init_roles_payload:
                # TODO custom exception (?)
                raise ValueError(f"Top Level role {role} not found in payload.")

            public_keys[role] = init_roles_payload[role].get("keys")
            expiration[role] = init_roles_payload[role].get("expiration")
            threshold[role] = init_roles_payload[role].get("threshold")

            if len(public_keys[role]) < threshold[role]:
                # TODO custom exception (?)
                missing_keys_num = threshold[role] - len(public_keys[role])
                raise ValueError(
                    f"Role {role} has {missing_keys_num} missing Public Key(s) "
                    f"to match to defined threshold {threshold[role]}."
                )

        roles[Targets.type] = Metadata[Targets](
            signed=Targets(
                version=1,
                spec_version=SPEC_VERSION,
                expires=expiration[Targets.type],
                targets={}
            ),
            signatures={},
        )
        roles[Snapshot.type] = Metadata[Snapshot](
            Snapshot(
                version=1,
                spec_version=SPEC_VERSION,
                expires=expiration[Snapshot.type],
                meta={"targets.json": MetaFile(version=1)},
            ),
            {},
        )
        roles[Timestamp.type] = Metadata[Timestamp](
            Timestamp(
                version=1,
                spec_version=SPEC_VERSION,
                expires=expiration[Timestamp.type],
                snapshot_meta=MetaFile(version=1),
            ),
            {},
        )

        roles_public_keys = [
            key for keys in public_keys.values() for key in keys
        ]

        roles_keyids = dict()
        for rolename in public_keys:
            roles_keyids[rolename] = {"keyids": list()}
            for role_key in public_keys[rolename]:
                roles_keyids[rolename]["keyids"].append(role_key["keyid"])

        roles[Root.type] = Metadata[Root](
            signed=Root(
                version=1,
                spec_version=SPEC_VERSION,
                expires=expiration[Root.type],
                keys={
                    key["keyid"]: Key.from_securesystemslib_key(key)
                    for key in roles_public_keys
                },
                roles={
                    role: Role(
                        keys["keyids"],
                        threshold=threshold[role]
                    )
                    for role, keys in roles_keyids.items()
                },
                consistent_snapshot=True,
            ),
            signatures={},
        )

        metadata_file = list()
        for role in TOP_LEVEL_ROLE_NAMES:
            if role == Timestamp.type:
                filename = f"{roles[role].signed.type}.json"
            else:
                filename = f"{roles[role].signed.version}.{roles[role].signed.type}.json"

            metadata_file.append(
                TUFRepositoryFiles(
                    filename,
                    roles[role]
                )
            )

        self._is_initialized = True
        return metadata_file

    def store(self, filename: str, data: Metadata) -> None:
        data.to_file(filename, JSONSerializer(), self.storage_backend)

    def load(self, rolename: str) -> "Metadata[T]":
        return Metadata.from_file(rolename, None, self.storage_backend)

    def sign(self, sign_roles_payload: dict) -> None:
        
        root_md = self.load(Root.type)

        for role in sign_roles_payload:
            number_keys = len(sign_roles_payload[role].get("keys"))
            if root_md.signed.roles[role].threshold < number_keys:
                raise ValueError(
                    "Number of keys {number_keys} is lower than defined "
                    "{role} threshold {root_md.signed.roles[role].threshold}"
                )

            for key in sign_roles_payload[role].get("keys"):
                md_role = self.load(role)
                signer = SSlibSigner(key)
                md_role.sign(signer)

            if role == Timestamp.type:
                filename = f"{md_role.signed.type}.json"
            else:
                filename = f"{md_role.signed.version}.{md_role.signed.type}.json"
                  
            self.store(filename, md_role)
