from __future__ import annotations

import pytest

from tests.e2e.conftest import RUNEX_PATH

pytestmark = pytest.mark.integration


class TestBasicExec:

    def test_whoami_returns_target_user(self, ga, disposable_user, runex_deployed):
        user, password = disposable_user
        result = ga.exec_argv(RUNEX_PATH, [user, password, "-P", "--", "whoami.exe"])
        assert result.exitcode == 0, f"stdout={result.stdout} stderr={result.stderr}"
        assert user.lower() in result.stdout.lower()

    def test_verbose_output(self, ga, disposable_user, runex_deployed):
        user, password = disposable_user
        result = ga.exec_argv(RUNEX_PATH, [user, password, "-v", "-P", "--", "whoami.exe"])
        assert result.exitcode == 0
        assert "[*]" in result.stdout


class TestRaceConditionRegression:

    def test_privilege_enumeration_no_crash(self, ga, disposable_user, runex_deployed):
        """Regression: freshly created user + immediate RunEx should not AccessViolation."""
        user, password = disposable_user
        for i in range(10):
            result = ga.exec_argv(RUNEX_PATH, [user, password, "-P", "-v", "--", "whoami.exe"])
            assert "AccessViolationException" not in result.stdout, f"Crash on iteration {i}"
            assert "AccessViolationException" not in result.stderr, f"Crash on iteration {i}"
            assert result.exitcode == 0, (
                f"Iteration {i}: exit={result.exitcode} "
                f"stdout={result.stdout} stderr={result.stderr}"
            )


class TestNegativeCases:

    def test_bad_credentials(self, ga, runex_deployed):
        result = ga.exec_argv(RUNEX_PATH, [
            "_no_such_user_xyz", "wrongpass", "-P", "--", "whoami.exe",
        ])
        combined = result.stdout + result.stderr
        assert result.exitcode != 0 or "RunExException" in combined

    def test_nonexistent_user(self, ga, runex_deployed):
        result = ga.exec_argv(RUNEX_PATH, [
            "_ghost_user_404", "P@ss123!", "-P", "--", "whoami.exe",
        ])
        combined = result.stdout + result.stderr
        assert result.exitcode != 0 or "RunExException" in combined


class TestIOModes:

    def test_background_mode(self, ga, disposable_user, runex_deployed):
        user, password = disposable_user
        result = ga.exec_argv(RUNEX_PATH, [
            user, password, "-t", "0", "--", "cmd.exe", "/c", "echo", "hello",
        ])
        assert result.exitcode == 0
        stdout_lower = result.stdout.lower()
        assert "pid" in stdout_lower or "background" in stdout_lower

    def test_passthrough_exit_code(self, ga, disposable_user, runex_deployed):
        user, password = disposable_user
        result = ga.exec_argv(RUNEX_PATH, [
            user, password, "-P", "--", "cmd.exe", "/c", "exit", "/b", "42",
        ])
        assert result.exitcode == 42, (
            f"Expected exit code 42, got {result.exitcode}. "
            f"stdout={result.stdout}"
        )


class TestLogonTypes:

    @pytest.mark.parametrize("logon_type", ["interactive", "cleartext"])
    def test_logon_type_succeeds(self, ga, disposable_user, runex_deployed, logon_type):
        user, password = disposable_user
        result = ga.exec_argv(RUNEX_PATH, [
            user, password, "-l", logon_type, "-P", "--", "whoami.exe",
        ])
        assert result.exitcode == 0, (
            f"logon_type={logon_type} exit={result.exitcode} "
            f"stdout={result.stdout} stderr={result.stderr}"
        )
        assert user.lower() in result.stdout.lower()


class TestProfile:

    def test_force_profile(self, ga, disposable_user, runex_deployed):
        user, password = disposable_user
        result = ga.exec_argv(RUNEX_PATH, [
            user, password, "-p", "-P", "--", "whoami.exe",
        ])
        assert result.exitcode == 0
        assert user.lower() in result.stdout.lower()


class TestUACBypass:

    def test_bypass_uac_with_withlogon(self, ga, disposable_admin, runex_deployed):
        user, password = disposable_admin
        result = ga.exec_argv(RUNEX_PATH, [
            user, password,
            "--bypass-uac", "-f", "withlogon", "-P", "--",
            "whoami.exe", "/priv",
        ])
        assert result.exitcode == 0, (
            f"exit={result.exitcode} stdout={result.stdout} stderr={result.stderr}"
        )


class TestPipeMode:

    def test_pipe_captures_output(self, ga, disposable_user, runex_deployed):
        user, password = disposable_user
        result = ga.exec_argv(RUNEX_PATH, [user, password, "--", "whoami.exe"])
        assert result.exitcode == 0, f"stdout={result.stdout} stderr={result.stderr}"
        assert user.lower() in result.stdout.lower()

    def test_pipe_exit_code(self, ga, disposable_user, runex_deployed):
        user, password = disposable_user
        result = ga.exec_argv(RUNEX_PATH, [
            user, password, "--", "cmd.exe", "/c", "exit", "/b", "42",
        ])
        assert result.exitcode == 42, (
            f"Expected exit 42, got {result.exitcode}. stdout={result.stdout}"
        )


class TestNewCredsLogon:

    def test_newcreds_logon_succeeds(self, ga, disposable_user, runex_deployed):
        user, password = disposable_user
        result = ga.exec_argv(RUNEX_PATH, [
            user, password, "-l", "newcreds", "-f", "withlogon",
            "-P", "--", "whoami.exe",
        ])
        combined = result.stdout + result.stderr
        assert "Exception" not in combined, f"Crash: {combined}"
        assert result.exitcode == 0, (
            f"exit={result.exitcode} stdout={result.stdout} stderr={result.stderr}"
        )


class TestCreateProcessFunctions:

    def test_withtoken_function(self, ga, disposable_admin, runex_deployed):
        user, password = disposable_admin
        result = ga.exec_argv(RUNEX_PATH, [
            user, password, "-f", "withtoken", "-P", "--", "whoami.exe",
        ])
        assert result.exitcode == 0, (
            f"exit={result.exitcode} stdout={result.stdout} stderr={result.stderr}"
        )
        assert user.lower() in result.stdout.lower()

    def test_impersonate_mode(self, ga, disposable_admin, runex_deployed):
        """Verify -i (remote impersonation) path executes without crashing.

        whoami fails under thread impersonation (Access Denied querying
        the impersonation token), so we use echo to verify the path works.
        """
        user, password = disposable_admin
        result = ga.exec_argv(RUNEX_PATH, [
            user, password, "-i", "-l", "cleartext", "--",
            "cmd.exe", "/c", "echo", "impersonate-ok",
        ])
        assert result.exitcode == 0, (
            f"exit={result.exitcode} stdout={result.stdout} stderr={result.stderr}"
        )
        assert "impersonate-ok" in result.stdout


class TestCommandParsing:

    def test_multiword_command_no_separator(self, ga, disposable_user, runex_deployed):
        user, password = disposable_user
        result = ga.exec_argv(RUNEX_PATH, [
            user, password, "cmd", "/c", "echo", "test-marker-e2e",
        ])
        assert "test-marker-e2e" in result.stdout

    def test_special_chars_in_password(self, ga, runex_deployed):
        user = "_runex_specpw"
        password = "P@ss&W0rd!^2"
        ga.exec_argv("net.exe", ["user", user, "/delete"], timeout=30)
        created = ga.exec_argv("net.exe", ["user", user, password, "/add"], timeout=30)
        assert created.exitcode == 0, f"Failed to create user: {created.stderr}"
        try:
            result = ga.exec_argv(RUNEX_PATH, [
                user, password, "-P", "--", "whoami.exe",
            ])
            assert result.exitcode == 0, (
                f"exit={result.exitcode} stdout={result.stdout} stderr={result.stderr}"
            )
            assert user.lower() in result.stdout.lower()
        finally:
            ga.exec_argv("net.exe", ["user", user, "/delete"], timeout=30)


class TestNegativeBypassUac:

    def test_bypass_uac_incompatible_function(self, ga, disposable_admin, runex_deployed):
        user, password = disposable_admin
        result = ga.exec_argv(RUNEX_PATH, [
            user, password, "--bypass-uac", "-f", "withtoken",
            "-P", "--", "whoami.exe",
        ])
        combined = result.stdout + result.stderr
        assert "not compatible with" in combined, (
            f"Expected 'not compatible with' error. stdout={result.stdout}"
        )


class TestTimeout:

    def test_timeout_expiry_still_active(self, ga, disposable_user, runex_deployed):
        user, password = disposable_user
        result = ga.exec_argv(RUNEX_PATH, [
            user, password, "-t", "1", "--",
            "ping.exe", "-n", "10", "127.0.0.1",
        ])
        assert result.exitcode == 259, (
            f"Expected 259 (STILL_ACTIVE), got {result.exitcode}. "
            f"stdout={result.stdout}"
        )
