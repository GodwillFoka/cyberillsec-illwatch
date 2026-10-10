"""Primitives de sécurité — hachage des mots de passe et jetons d'accès JWT (MOD-01).

Choix techniques :
  * Argon2id (via `pwdlib`) pour le hachage : lauréat de la Password Hashing
    Competition, recommandé par l'OWASP, résistant aux attaques GPU.
  * JWT HS256 signé avec `SECRET_KEY`, durée de vie courte
    (`ACCESS_TOKEN_EXPIRE_MINUTES`, 15 min). L'algorithme est figé au décodage pour
    interdire toute attaque par substitution (`alg: none`, confusion RS/HS).
  * Rotation de clé (M7 lot 2) : chaque jeton porte l'empreinte de sa clé (`kid`). La clé
    courante signe ; `SECRET_KEY_PREVIOUS` est encore acceptée en vérification, le temps que
    les jetons qu'elle a signés expirent. Un `kid` inconnu est refusé sans essai de clé.
"""

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt
from pwdlib import PasswordHash

from illwatch.app.config import Settings, get_settings

JWT_ALGORITHM = "HS256"
TOKEN_TYPE_ACCESS = "access"  # noqa: S105 - discriminant de jeton, pas un secret
MIN_PASSWORD_LENGTH = 12

_password_hash = PasswordHash.recommended()

# Hash factice : vérifié quand l'utilisateur n'existe pas, pour que le temps de
# réponse de /auth/token ne révèle pas si un identifiant est enregistré.
_DUMMY_HASH = _password_hash.hash("illwatch-timing-equalizer")


class InvalidTokenError(Exception):
    """Jeton absent, expiré, mal signé ou de mauvais type."""


class WeakPasswordError(ValueError):
    """Mot de passe refusé par la politique minimale."""


@dataclass(frozen=True, slots=True)
class TokenPayload:
    """Revendications utiles extraites d'un jeton validé."""

    user_id: UUID
    role: str
    expires_at: int = 0  # horodatage Unix de l'expiration (`exp`)


def validate_password_policy(password: str) -> None:
    """Politique minimale : longueur (NIST SP 800-63B privilégie la longueur à la complexité)."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(
            f"Le mot de passe doit contenir au moins {MIN_PASSWORD_LENGTH} caractères."
        )


def hash_password(password: str) -> str:
    """Retourne l'empreinte Argon2id d'un mot de passe."""
    return _password_hash.hash(password)


def verify_password(password: str, hashed_password: str | None) -> bool:
    """Vérifie un mot de passe en temps quasi constant, même si l'utilisateur n'existe pas."""
    if hashed_password is None:
        _password_hash.verify(password, _DUMMY_HASH)
        return False
    return _password_hash.verify(password, hashed_password)


def key_id(secret: str) -> str:
    """Empreinte publique d'une clé (16 caractères hexadécimaux) : identifie sans révéler."""
    return hashlib.sha256(secret.encode()).hexdigest()[:16]


def _verification_keys(cfg: Settings) -> dict[str, str]:
    keys = {key_id(cfg.secret_key): cfg.secret_key}
    if cfg.secret_key_previous is not None:
        previous = cfg.secret_key_previous.get_secret_value()
        keys.setdefault(key_id(previous), previous)
    return keys


def create_access_token(
    user_id: UUID,
    role: str,
    *,
    settings: Settings | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Émet un jeton d'accès signé pour un utilisateur."""
    cfg = settings or get_settings()
    now = datetime.now(UTC)
    expire = now + (expires_delta or timedelta(minutes=cfg.access_token_expire_minutes))
    claims = {
        "sub": str(user_id),
        "role": role,
        "type": TOKEN_TYPE_ACCESS,
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(
        claims, cfg.secret_key, algorithm=JWT_ALGORITHM, headers={"kid": key_id(cfg.secret_key)}
    )


def decode_access_token(token: str, *, settings: Settings | None = None) -> TokenPayload:
    """Valide signature, expiration et type d'un jeton, puis en extrait les revendications.

    Raises:
        InvalidTokenError: pour toute anomalie — le détail n'est jamais renvoyé au client.
    """
    cfg = settings or get_settings()
    keys = _verification_keys(cfg)
    try:
        kid = jwt.get_unverified_header(token).get("kid")
        # Jeton antérieur à la rotation (sans `kid`) : seule la clé courante est essayée.
        secret = keys.get(str(kid)) if kid is not None else cfg.secret_key
        if secret is None:
            raise InvalidTokenError("Clé de signature inconnue ou retirée.")
        claims = jwt.decode(
            token,
            secret,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["sub", "exp", "iat", "type"]},
        )
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(str(exc)) from exc

    if claims.get("type") != TOKEN_TYPE_ACCESS:
        raise InvalidTokenError("Type de jeton inattendu.")
    try:
        user_id = UUID(str(claims["sub"]))
    except ValueError as exc:
        raise InvalidTokenError("Sujet de jeton invalide.") from exc

    return TokenPayload(
        user_id=user_id, role=str(claims.get("role", "")), expires_at=int(claims["exp"])
    )
