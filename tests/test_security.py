"""Tests des primitives de sécurité : hachage Argon2id et jetons JWT."""

from datetime import timedelta
from uuid import uuid4

import jwt
import pytest

from sentry.app.config import Settings
from sentry.app.security import (
    JWT_ALGORITHM,
    InvalidTokenError,
    WeakPasswordError,
    create_access_token,
    decode_access_token,
    hash_password,
    validate_password_policy,
    verify_password,
)

SETTINGS = Settings(secret_key="k" * 64)


def test_hash_est_argon2id_et_sale() -> None:
    h1, h2 = hash_password("correct horse battery"), hash_password("correct horse battery")
    assert h1.startswith("$argon2id$")
    assert h1 != h2  # sel aléatoire


def test_verification_du_mot_de_passe() -> None:
    hashed = hash_password("correct horse battery")
    assert verify_password("correct horse battery", hashed) is True
    assert verify_password("mauvais mot de passe", hashed) is False


def test_verification_sans_utilisateur_retourne_faux() -> None:
    assert verify_password("peu importe", None) is False


def test_politique_de_longueur() -> None:
    with pytest.raises(WeakPasswordError):
        validate_password_policy("trop-court")
    validate_password_policy("suffisamment-long")


def test_aller_retour_du_jeton() -> None:
    user_id = uuid4()
    token = create_access_token(user_id, "ANALYST", settings=SETTINGS)
    payload = decode_access_token(token, settings=SETTINGS)
    assert payload.user_id == user_id
    assert payload.role == "ANALYST"


def test_jeton_expire_refuse() -> None:
    token = create_access_token(
        uuid4(), "ANALYST", settings=SETTINGS, expires_delta=timedelta(seconds=-1)
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, settings=SETTINGS)


def test_jeton_signe_avec_une_autre_cle_refuse() -> None:
    token = create_access_token(uuid4(), "ADMIN", settings=Settings(secret_key="z" * 64))
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, settings=SETTINGS)


def test_algorithme_none_refuse() -> None:
    forged = jwt.encode(
        {"sub": str(uuid4()), "type": "access", "iat": 0, "exp": 9999999999},
        key="",
        algorithm="none",
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(forged, settings=SETTINGS)


def test_type_de_jeton_inattendu_refuse() -> None:
    forged = jwt.encode(
        {"sub": str(uuid4()), "type": "refresh", "iat": 0, "exp": 9999999999},
        SETTINGS.secret_key,
        algorithm=JWT_ALGORITHM,
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(forged, settings=SETTINGS)


def test_sujet_non_uuid_refuse() -> None:
    forged = jwt.encode(
        {"sub": "admin", "type": "access", "iat": 0, "exp": 9999999999},
        SETTINGS.secret_key,
        algorithm=JWT_ALGORITHM,
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(forged, settings=SETTINGS)
