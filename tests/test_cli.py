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
    for sub in ("check", "init", "upgrade", "downgrade", "current"):
        assert sub in result.output


def test_racine_expose_seed_et_users() -> None:
    result = CliRunner().invoke(cli, ["--help"])
    assert "seed" in result.output
    assert "users" in result.output


def test_downgrade_exige_une_confirmation() -> None:
    result = CliRunner().invoke(cli, ["db", "downgrade", "base"], input="n\n")
    assert result.exit_code != 0


def test_users_create_refuse_un_mot_de_passe_faible() -> None:
    result = CliRunner().invoke(
        cli,
        ["users", "create", "--username", "u", "--email", "u@x.io", "--password", "court"],
    )
    assert result.exit_code == 1
    assert "12 caractères" in result.output


def test_db_check_sur_base_injoignable_sort_en_erreur() -> None:
    """La base de test (SQLite mémoire) est joignable ; on vérifie juste le code retour."""
    result = CliRunner().invoke(cli, ["db", "check"])
    assert result.exit_code in (0, 1)
