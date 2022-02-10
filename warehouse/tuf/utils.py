# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import datetime

from contextlib import contextmanager
from io import BytesIO
from tuf.api.metadata import (
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Delegations,
    Key,
    Metadata,
    MetaFile,
    Role,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from typing import Dict, Any

import tuf.formats
import tuf.repository_lib

from google.cloud.exceptions import GoogleCloudError, NotFound
from securesystemslib.exceptions import StorageError
from securesystemslib.interface import generate_and_write_ed25519_keypair
from securesystemslib.signer import SSlibSigner
from securesystemslib.storage import FilesystemBackend, StorageBackendInterface
from tuf.api import metadata
from tuf.api.serialization.json import JSONSerializer


from warehouse.tuf.constants import BIN_N_COUNT, SPEC_VERSION
from warehouse.config import Environment


def _key_service(config):
    key_service_class = config.maybe_dotted(config.registry.settings["tuf.key_backend"])
    return key_service_class.create_service(None, config)


def _repository_service(config):
    repo_service_class = config.maybe_dotted(
        config.registry.settings["tuf.repo_backend"]
    )
    return repo_service_class.create_service(None, config)


def _set_expiration_for_role(config, role_name):
    # If we're initializing TUF for development purposes, give
    # every role a long expiration time so that developers don't have to
    # continually re-initialize it.
    if config.registry.settings["warehouse.env"] == Environment.development:
        return datetime.datetime.now() + datetime.timedelta(
            seconds=config.registry.settings["tuf.development_metadata_expiry"]
        )
    else:
        return datetime.datetime.now() + datetime.timedelta(
            seconds=config.registry.settings[f"tuf.{role_name}.expiry"]
        )


def init_repository(config):
    """
    Initialize the TUF repository from scratch, including a brand new root.
    """
    PRETTY = JSONSerializer(compact=False)

    repository_service = _repository_service(config)
    key_service = _key_service(config)

    roles: Dict[str, Metadata] = dict()
    keys: Dict[str, Key] = dict()

    for role in TOP_LEVEL_ROLE_NAMES:
        keys[role] = key_service.pubkeys_for_role(role)

    roles[Targets.type] = Metadata[Targets](
        signed=Targets(
            version=1,
            spec_version=SPEC_VERSION,
            expires=_set_expiration_for_role(config, Targets.type),
            targets={}
        ),
        signatures={},
    )
    roles[Snapshot.type] = Metadata[Snapshot](
        Snapshot(
            version=1,
            spec_version=SPEC_VERSION,
            expires=_set_expiration_for_role(config, Snapshot.type),
            meta={"targets.json": MetaFile(version=1)},
        ),
        {},
    )    
    roles[Timestamp.type] = Metadata[Timestamp](
        Timestamp(
            version=1,
            spec_version=SPEC_VERSION,
            expires=_set_expiration_for_role(config, Timestamp.type),
            snapshot_meta=MetaFile(version=1),
        ),
        {},
    )
    roles[Root.type] = Metadata[Root](
        signed=Root(
            version=1,
            spec_version=SPEC_VERSION,
            expires=_set_expiration_for_role(config, Root.type),
            keys={
                key["keyid"]: Key.from_securesystemslib_key(key)
                for key in keys.values()
            },
            roles={
                role: Role(
                    [key["keyid"]],
                    threshold=config.registry.settings[f"tuf.{role}.threshold"]
                )
                for role, key in keys.items()
            },
            consistent_snapshot=True,
        ),
        signatures={},
    )

    for role in TOP_LEVEL_ROLE_NAMES:
        key = key_service.privkeys_for_role(role)
        signer = SSlibSigner(key)
        roles[role].sign(signer)

    for role in TOP_LEVEL_ROLE_NAMES:
        filename = f"{roles[role].signed.version}.{roles[role].signed.type}.json"
        path = os.path.join(repository_service._repo_path, filename)
        roles[role].to_file(path, serializer=PRETTY)

    roles[Timestamp.type].to_file(
        os.path.join(repository_service._repo_path, "timestamp.json"),
        serializer=PRETTY
    )


def create_dev_keys(password: str, filepath: str) -> None:
    generate_and_write_ed25519_keypair(password, filepath=filepath)


def make_fileinfo(file, custom=None):
    """
    Given a warehouse.packaging.models.File, create a TUF-compliant
    "fileinfo" dictionary suitable for addition to a delegated bin.

    The optional "custom" kwarg can be used to supply additional custom
    metadata (e.g., metadata for indicating backsigning).
    """
    hashes = {"blake2b": file.blake2_256_digest}
    fileinfo = tuf.formats.make_targets_fileinfo(file.size, hashes, custom=custom)

    return fileinfo


def bump_metadata(metadata, delta):
    """
    Given a tuf.api.metadata.Signed, bump its version and expiration (with the given
    timedelta).
    """
    metadata.bump_version()
    metadata.bump_expiration(delta=delta)


def find_snapshot(timestamp, storage_backend):
    """
    Given a tuf.api.metadata.Timestamp model, return the Metadata container
    for the consistent snapshot that it references.
    """
    snapshot_version = timestamp.meta["snapshot.json"]["version"]

    return metadata.Metadata.from_json_file(
        f"{snapshot_version}.snapshot.json", storage_backend
    )


def find_delegated_bin(filepath, snapshot, storage_backend):
    """
    Given a new target filepath and a tuf.api.metadata.Snapshot model,
    return a tuple of the bin name and tup.api.metadata.Metadata container for
    the consistent delegated targets bin that the target belongs in.
    """

    # TODO: This probably isn't using the right hash function.
    filepath_hash = tuf.repository_lib.get_target_hash(filepath)
    bin_name = tuf.repository_lib.find_bin_for_target_hash(filepath_hash, BIN_N_COUNT)
    bin_version = snapshot.meta[f"{bin_name}.json"]["version"]

    return bin_name, metadata.Metadata.from_json_file(
        f"{bin_version}.{bin_name}.json", storage_backend
    )


class LocalBackend(StorageBackendInterface):
    def __init__(self, request):
        self._filesystem_backend = FilesystemBackend()
        self._repo_path = os.path.join(
            request.registry.settings["tuf.repo.path"], "metadata.staged"
        )

    def get(self, filepath):
        return self._filesystem_backend.get(os.path.join(self._repo_path, filepath))

    def put(self, fileobj, filepath):
        return self._filesystem_backend.put(
            fileobj, os.path.join(self._repo_path, filepath)
        )

    def remove(self, filepath):
        return self._filesystem_backend.remove(os.path.join(self._repo_path, filepath))

    def getsize(self, filepath):
        return self._filesystem_backend.getsize(os.path.join(self._repo_path, filepath))

    def create_folder(self, filepath):
        return self._filesystem_backend.create_folder(
            os.path.join(self._repo_path, filepath)
        )

    def list_folder(self, filepath):
        return self._filesystem_backend.list_folder(
            os.path.join(self._repo_path, filepath)
        )


class GCSBackend(StorageBackendInterface):
    def __init__(self, request):
        self._client = request.find_service(name="gcloud.gcs")
        # NOTE: This needs to be created.
        self._bucket = self._client.get_bucket(request.registry.settings["tuf.bucket"])

    @contextmanager
    def get(self, filepath):
        try:
            contents = self._bucket.blob(filepath).download_as_string()
            yield BytesIO(contents)
        except NotFound as e:
            raise StorageError(f"{filepath} not found")

    def put(self, fileobj, filepath):
        try:
            blob = self._bucket.blob(filepath)
            # NOTE(ww): rewind=True reflects the behavior of the securesystemslib
            # implementation of StorageBackendInterface, which seeks to the file start.
            # I'm not sure it's actually required.
            blob.upload_from_file(fileobj, rewind=True)
        except GoogleCloudError:
            # TODO: expose details of the underlying error in the message here?
            raise StorageError(f"couldn't store to {filepath}")

    def remove(self, filepath):
        try:
            self._bucket.blob(filepath).delete()
        except NotFound:
            raise StorageError(f"{filepath} not found")

    def getsize(self, filepath):
        blob = self._bucket.get_blob(filepath)

        if blob is None:
            raise StorageError(f"{filepath} not found")

        return blob.size

    def create_folder(self, filepath):
        if not filepath:
            return

        if not filepath.endswith("/"):
            filepath = f"{filepath}/"

        try:
            blob = self._bucket.blob(filepath)
            blob.upload_from_string(b"")
        except GoogleCloudError as e:
            raise StorageError(f"couldn't create folder: {filepath}")

    def list_folder(self, filepath):
        if not filepath.endswith("/"):
            filepath = f"{filepath}/"

        # NOTE: The `nextPageToken` appears to be required due to an implementation detail leak.
        # See https://github.com/googleapis/google-cloud-python/issues/7875
        blobs = self._client.list_blobs(
            self._bucket, prefix=filepath, fields="items(name),nextPageToken"
        )
        return [blob.name for blob in blobs]
