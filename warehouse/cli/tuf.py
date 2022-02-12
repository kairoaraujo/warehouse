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

import datetime
import hashlib
import click


from warehouse.cli import warehouse
from warehouse.config import Environment
from warehouse.tuf import utils
from warehouse.tuf.constants import BIN_N_COUNT, Role
from warehouse.tuf.metadata_repo.repository import (
    TOP_LEVEL_ROLE_NAMES,
    MetadataRepository,
)


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
    utils.create_dev_keys(config.registry.settings[f"tuf.{name_}.secret"], path_)


@tuf.command()
@click.pass_obj
def new_repo(config):
    """
    Initialize the TUF repository from scratch, including a brand new root.
    """

    key_service = _key_service(config)
    storage_service = _repository_service(config)
    md_repository = MetadataRepository(storage_service, key_service)

    if md_repository._is_initialized:
        raise click.ClickException("TUF Metadata Repository already initialized.")

    init_roles_payload = dict()
    for role in TOP_LEVEL_ROLE_NAMES:
        init_roles_payload[role] = {
            "keys": [key_service.get(role, "public")],
            "expiration": _set_expiration_for_role(config, role),
            "threshold": config.registry.settings[f"tuf.{role}.threshold"],
        }

    try:
        metadata_repo_files = md_repository.initialize(init_roles_payload)
    except (ValueError, FileExistsError) as err:
        raise click.ClickException(str(err))

    for repo_file in metadata_repo_files:
        md_repository.store(repo_file.filename, repo_file.data)

    if md_repository.is_initialized is False:
        raise click.ClickException("TUF Metadata Repository failed to initialized.")

    sign_roles_payload = dict()
    for role in TOP_LEVEL_ROLE_NAMES:
        sign_roles_payload[role] = {
            "keys": [key_service.get(role, "private")],
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

    key_service = _key_service(config)
    storage_service = _repository_service(config)
    md_repository = MetadataRepository(storage_service, key_service)    

    delegate_roles_payload = dict()
    
    delegate_roles_payload[Role.BINS.value] = {
        "delegator": Role.TARGETS.value,
        "keys": [key_service.get(Role.BINS.value, "private")],
        "expiration": _set_expiration_for_role(config, Role.BINS.value),
        "threshold": config.registry.settings[f"tuf.{Role.BINS.value}.threshold"],
        "paths": ["*"]
    }
    delegate_roles_payload[Role.BIN_N.value] = {
        "delegator": Role.BINS.value,
        "keys": [key_service.get(Role.BIN_N.value, "private")],
        "expiration": _set_expiration_for_role(config, Role.BIN_N.value),
        "threshold": config.registry.settings[f"tuf.{Role.BIN_N.value}.threshold"],
        "path_hash_prefixes": []
    }        
    md_repository.add_delegation(delegate_roles_payload)


@tuf.command()
@click.pass_obj
def add_targets(config):
    # """
    # Collect the "paths" for every PyPI package. These are packages already in
    # existence, so we'll add some additional data to their targets to
    # indicate that we're back-signing them.
    # """
    # from warehouse.db import Session
    # from warehouse.packaging.models import File, Release, Project
  
    # key_service = _key_service(config)
    # storage_service = _repository_service(config)
    # md_repository = MetadataRepository(storage_service, key_service)
    
    # db = Session(bind=config.registry["sqlalchemy.engine"])
    # for file in db.query(File).all():
    #     project = db.query(Release).filter(file.release_id == Release.id).one().project
    #     fileinfo = _make_backsigned_fileinfo_from_file(file)
        


        
