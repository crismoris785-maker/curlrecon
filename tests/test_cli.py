from click.testing import CliRunner

from curlrecon.cli import cli


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "CurlRecon - Advanced CLI Reconnaissance Tool" in result.output


def test_cli_missing_target():
    runner = CliRunner()
    result = runner.invoke(cli, [])
    # It should hit the interactive menu and abort since there's no input
    assert result.exit_code != 0
    assert "CurlRecon Interactive Menu" in result.output
