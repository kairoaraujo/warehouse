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

import click
import datetime

from warehouse.cli import warehouse
from warehouse.config import Environment
from warehouse.tuf import utils
from warehouse.tuf.metadata_repo.repository import (
    MetadataRepository,
    TOP_LEVEL_ROLE_NAMES
)
from warehouse.tuf.constants import BIN_N_COUNT
from tuf.api.metadata import Role


def _make_backsigned_fileinfo_from_file(file):
    return utils.make_fileinfo(file, custom={"backsigned": True})


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
        return datetime.datetime.now().replace(microsecond=0) + datetime.timedelta(
            seconds=config.registry.settings["tuf.development_metadata_expiry"]
        )
    else:
        return datetime.datetime.now().replace(microsecond=0) + datetime.timedelta(
            seconds=config.registry.settings[f"tuf.{role_name}.expiry"]
        )


@warehouse.group()  # pragma: no-branch
def tuf():
    """
    Manage Warehouse's TUF state.
    """


@tuf.command()
@click.pass_obj
@click.option("--name", "name_", help="The name of the TUF role for this keypair")
@click.option("--path", "path_", help="The basename of the Ed25519 keypair to generate")
def keypair(config, name_, path_):
    """
    Generate a new TUF keypair, for development purposes.
    """
    utils.create_dev_keys(
        config.registry.settings[f"tuf.{name_}.secret"], path_
    )


@tuf.command()
@click.pass_obj
def new_repo(config):
    """
    Initialize the TUF repository from scratch, including a brand new root.
    """
    
    key_service = _key_service(config)
    storage_service = _repository_service(config)
    md_repository = MetadataRepository(storage_service)

    if md_repository._is_initialized:
        raise click.ClickException(
            "TUF Metadata Repository already initialized."
        )
    
    init_roles_payload = dict()
    for role in TOP_LEVEL_ROLE_NAMES:
        init_roles_payload[role] = {
            "keys": [key_service.get(role, "public")],
            "expiration": _set_expiration_for_role(config, role),
            "threshold": config.registry.settings[f"tuf.{role}.threshold"]
        }

    try:
        metadata_repo_files = md_repository.initialize(init_roles_payload)
    except (ValueError, FileExistsError) as err:
        raise click.ClickException(str(err))

    for repo_file in metadata_repo_files:
        md_repository.store(repo_file.filename, repo_file.data)
    
    if md_repository.is_initialized is False:
         raise click.ClickException(
            "TUF Metadata Repository failed to initialized."
        )

    sign_roles_payload = dict()
    for role in TOP_LEVEL_ROLE_NAMES:
        sign_roles_payload[role] = {
            "keys": [key_service.get(role, "private")]
        }

    try:
        md_repository.sign(sign_roles_payload)
    except ValueError as err:
        raise click.ClickException(str(err))
    
    
@tuf.command()
@click.pass_obj
def build_targets(config):
    """
    Given an initialized (but empty) TUF repository, create the delegated
    targets role (bins) and its hashed bin delegations (each bin-n).
    """


    """
    repo_service = _repository_service(config)
    repository = repo_service.load_repository()

    # Load signing keys. We do this upfront for the top-level roles.
    key_service = _key_service(config)
    for role in ["snapshot", "targets", "timestamp"]:
        role_obj = getattr(repository, role)

        [role_obj.load_signing_key(k) for k in key_service.privkeys_for_role(role)]

    # NOTE: TUF normally does delegations by path patterns (i.e., globs), but PyPI
    # doesn't store its uploads on the same logical host as the TUF repository.
    # The last parameter to `delegate` is a special sentinel for this.
    repository.targets.delegate(
        Role.BINS.value, key_service.pubkeys_for_role(Role.BINS.value), ["*"]
    )
    bins_role = repository.targets(Role.BINS.value)
    _set_expiration_for_role(config, bins_role, Role.BINS.value)

    for privkey in key_service.privkeys_for_role(Role.BINS.value):
        bins_role.load_signing_key(privkey)

    bins_role.delegate_hashed_bins(
        [],
        key_service.pubkeys_for_role(Role.BIN_N.value),
        BIN_N_COUNT,
    )

    dirty_roles = ["snapshot", "targets", "timestamp", Role.BINS.value]
    for bin_n_role in bins_role.delegations:
        _set_expiration_for_role(config, bin_n_role, Role.BIN_N.value)
        dirty_roles.append(bin_n_role.rolename)

    for privkey in key_service.privkeys_for_role(Role.BIN_N.value):
        for bin_n_role in bins_role.delegations:
            bin_n_role.load_signing_key(privkey)

    # Collect the "paths" for every PyPI package. These are packages already in
    # existence, so we'll add some additional data to their targets to
    # indicate that we're back-signing them.
    from warehouse.db import Session
    from warehouse.packaging.models import File

    db = Session(bind=config.registry["sqlalchemy.engine"])
    for file in db.query(File).all():
        fileinfo = _make_backsigned_fileinfo_from_file(file)
        bins_role.add_target_to_bin(
            file.path,
            number_of_bins=BIN_N_COUNT,
            fileinfo=fileinfo,
        )

    repository.mark_dirty(dirty_roles)
    repository.writeall(
        consistent_snapshot=True,
        use_existing_fileinfo=True,
    )
    """