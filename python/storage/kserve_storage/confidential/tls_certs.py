# Copyright 2026 The KServe Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Fetch serving TLS material from CDH/KBS into the TEE-local cert directory."""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

from .secret_resolver import SecretResolver

logger = logging.getLogger(__name__)

DEFAULT_TLS_DIR = "/var/run/kserve/tls"

_CERT_FILENAME = "tls.crt"
_KEY_FILENAME = "tls.key"
_CA_FILENAME = "ca.crt"


def fetch_tls_certs(
    resolver: SecretResolver,
    cert_resource_id: str,
    key_resource_id: str,
    ca_resource_id: str | None = None,
    dest_dir: str = DEFAULT_TLS_DIR,
) -> list[Path]:
    """Retrieve TLS PEMs from CDH and write them under ``dest_dir``.

    Args:
        resolver: Secret resolver used to fetch each KBS resource.
        cert_resource_id: KBS resource ID for ``tls.crt``.
        key_resource_id: KBS resource ID for ``tls.key``.
        ca_resource_id: Optional KBS resource ID for ``ca.crt``.
        dest_dir: Directory that receives the PEM files.

    Returns:
        Paths of the files that were written.

    Raises:
        ValueError: If cert or key resource IDs are missing.
        SecretResolutionError: If CDH cannot return a resource.
    """
    if not cert_resource_id or not key_resource_id:
        raise ValueError(
            "CONFIDENTIAL_TLS_CERT_RESOURCE_ID and "
            "CONFIDENTIAL_TLS_KEY_RESOURCE_ID must both be set"
        )

    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    cert_path = dest / _CERT_FILENAME
    cert_path.write_bytes(resolver.resolve_key(cert_resource_id))
    written.append(cert_path)

    key_path = dest / _KEY_FILENAME
    key_path.write_bytes(resolver.resolve_key(key_resource_id))
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
    written.append(key_path)

    if ca_resource_id:
        ca_path = dest / _CA_FILENAME
        ca_path.write_bytes(resolver.resolve_key(ca_resource_id))
        written.append(ca_path)

    logger.info("Wrote confidential TLS material to %s (%d files)", dest, len(written))
    return written
