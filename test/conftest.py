# SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
# SPDX-License-Identifier: BSD-2-Clause

from pathlib import Path
from typing import Iterator, List

import pytest

from .device import new_qemu_tkey
from .tt.drivers.tkey import TKey, TKeyType
from .tt.drivers.tkey_runapp import TKeyRunapp


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--qemu-path", default="qemu-system-riscv32", help="Path to QEmu executable"
    )

    parser.addoption(
        "--qemu-usb-mux-path",
        default="qemu_usb_mux.py",
        help="Path to TKey USB controller simulator",
    )

    parser.addoption(
        "--tkey-runapp-path",
        default="tkey-runapp",
        help="Path to TKey-runapp",
    )


def pytest_report_header(config: pytest.Config) -> List[str]:
    qemu_path = Path(config.getoption("--qemu-path")).expanduser()
    qemu_usb_mux_path = Path(config.getoption("--qemu-usb-mux-path")).expanduser()

    return [f"qemu-path: {qemu_path}", f"qemu-usb-mux-path: {qemu_usb_mux_path}"]


@pytest.fixture(scope="session")
def qemu_path(request: pytest.FixtureRequest) -> Path:
    return Path(request.config.getoption("--qemu-path")).expanduser()


@pytest.fixture(scope="session")
def qemu_usb_mux_path(request: pytest.FixtureRequest) -> Path:
    return Path(request.config.getoption("--qemu-usb-mux-path")).expanduser()


@pytest.fixture(scope="session")
def tkey_runapp_path(request: pytest.FixtureRequest) -> Path:
    return Path(request.config.getoption("--tkey-runapp-path")).expanduser()


@pytest.fixture
def tkey(
    request: pytest.FixtureRequest,
    qemu_path: Path,
    qemu_usb_mux_path: Path,
    tmp_path: Path,
    tkey_runapp_path: Path,
) -> Iterator[TKey]:
    _tkey = new_qemu_tkey(TKeyType.CastorPre, qemu_path, qemu_usb_mux_path, tmp_path)
    _tkey.insert()
    # load fido-app
    TKeyRunapp(cli_path=tkey_runapp_path).load(_tkey, "../_bin/tkey_app/tkey_app.bin")
    yield _tkey
    _tkey.eject()
