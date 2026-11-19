from __future__ import annotations

import pytest

from winbox.config import Config
from winbox.vm import VM, GuestAgent, VMState

RUNEX_PATH = r"Z:\tools\RunEx.exe"


@pytest.fixture(scope="session")
def cfg():
    return Config.load()


@pytest.fixture(scope="session")
def ga(cfg):
    return GuestAgent(cfg)


@pytest.fixture(scope="session")
def vm(cfg):
    return VM(cfg)


@pytest.fixture(scope="session", autouse=True)
def running_vm(vm, ga):
    if vm.state() != VMState.RUNNING:
        vm.start()
    ga.wait(timeout=420)
    yield


@pytest.fixture(autouse=True)
def guest_is_healthy(vm, ga):
    if vm.state() is VMState.RUNNING and not ga.ping():
        ga.wait(timeout=60)
    yield


@pytest.fixture(scope="session")
def runex_deployed(ga):
    r = ga.exec(f"if exist {RUNEX_PATH} (exit /b 0) else (exit /b 1)")
    assert r.exitcode == 0, f"RunEx.exe not found at {RUNEX_PATH} on guest"


@pytest.fixture
def disposable_user(ga):
    user = "_runex_test"
    password = "T3stP@ss!rx"
    ga.exec_argv("net.exe", ["user", user, "/delete"], timeout=30)
    created = ga.exec_argv("net.exe", ["user", user, password, "/add"], timeout=30)
    assert created.exitcode == 0, f"Failed to create user: {created.stderr}"
    try:
        yield user, password
    finally:
        ga.exec_argv("net.exe", ["user", user, "/delete"], timeout=30)


@pytest.fixture
def disposable_admin(ga):
    user = "_runex_admin"
    password = "Adm!n_P@ss1"
    ga.exec_argv("net.exe", ["user", user, "/delete"], timeout=30)
    created = ga.exec_argv("net.exe", ["user", user, password, "/add"], timeout=30)
    assert created.exitcode == 0, f"Failed to create admin user: {created.stderr}"
    added = ga.exec_argv(
        "net.exe", ["localgroup", "Administrators", user, "/add"], timeout=30,
    )
    assert added.exitcode == 0, f"Failed to add to Administrators: {added.stderr}"
    try:
        yield user, password
    finally:
        ga.exec_argv("net.exe", ["user", user, "/delete"], timeout=30)
