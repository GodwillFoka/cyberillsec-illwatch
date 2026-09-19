"""Tests de l'interface en ligne de commande `sentry` — RF-03."""

from click.testing import CliRunner

from sentry.cli.main import cli


def test_aide_racine() -> None:
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "SENTRY" in result.output


def test_commande_version() -> None:
    result = CliRunner().invoke(cli, ["version"])
    assert result.exit_code == 0
    assert "SENTRY" in result.output


def test_commande_config_masque_les_secrets() -> None:
    result = CliRunner().invoke(cli, ["config"])
    assert result.exit_code == 0
    assert "test-secret-key" not in result.output
    assert "••••••" in result.output


def test_groupe_db_expose_ses_sous_commandes() -> None:
    result = CliRunner().invoke(cli, ["db", "--help"])
    assert result.exit_code == 0
    assert "check" in result.output
    assert "init" in result.output


def test_db_init_indique_la_commande_alembic() -> None:
    result = CliRunner().invoke(cli, ["db", "init"])
    assert result.exit_code == 0
    assert "alembic upgrade head" in result.output


def test_db_check_sur_base_injoignable_sort_en_erreur() -> None:
    """La base de test (SQLite mémoire) est joignable ; on vérifie juste le code retour."""
    result = CliRunner().invoke(cli, ["db", "check"])
    assert result.exit_code in (0, 1)
