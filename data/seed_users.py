#!/usr/bin/env python3
"""
Seed script to pre-populate the database with fake users using the Faker library.

Configuration is driven by environment variables (loaded from a .env file):

  DB_NAME          - database name            (default: vulnerable_bank)
  DB_USER          - database user            (default: postgres)
  DB_PASSWORD      - database password        (default: postgres)
  DB_HOST          - database host            (default: localhost)
  DB_PORT          - database port            (default: 5432)

  SEED_COUNT       - number of fake users to create        (default: 20)
  SEED_LOCALE      - Faker locale, e.g. en_US, fr_FR       (default: en_US)
  SEED_MIN_BALANCE - minimum starting account balance      (default: 100.00)
  SEED_MAX_BALANCE - maximum starting account balance      (default: 10000.00)
  SEED_CLEAR       - set to "true" to wipe existing non-admin users first
                     (default: false)

Usage:
  # from the project root
  python data/seed_users.py
"""

import os
import logging
import random
import string
import sys
from pathlib import Path

import psycopg2
from dotenv import load_dotenv
from faker import Faker

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Load environment variables
# ---------------------------------------------------------------------------
dotenv_path = os.getenv("DOTENV_PATH", Path(__file__).resolve().parent.parent / ".env")
load_dotenv(dotenv_path=dotenv_path, override=False)

# ---------------------------------------------------------------------------
# Database configuration
# ---------------------------------------------------------------------------
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "vulnerable_bank"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "postgres"),
    "host": os.getenv("DB_HOST", "localhost"),
    "port": os.getenv("DB_PORT", "5432"),
}

# ---------------------------------------------------------------------------
# Seed configuration
# ---------------------------------------------------------------------------
SEED_COUNT = int(os.getenv("SEED_COUNT", "20"))
SEED_LOCALE = os.getenv("SEED_LOCALE", "en_US")
SEED_MIN_BALANCE = float(os.getenv("SEED_MIN_BALANCE", "100.00"))
SEED_MAX_BALANCE = float(os.getenv("SEED_MAX_BALANCE", "10000.00"))
SEED_CLEAR = os.getenv("SEED_CLEAR", "false").strip().lower() == "true"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def generate_account_number(existing: set[str]) -> str:
    """Generate a unique 10-digit account number prefixed with ACC."""
    while True:
        suffix = "".join(random.choices(string.digits, k=10))
        account_number = f"ACC{suffix}"
        if account_number not in existing:
            existing.add(account_number)
            return account_number


def generate_reset_pin() -> str:
    """Generate a 6-digit numeric reset PIN."""
    return "".join(random.choices(string.digits, k=6))


def build_fake_users(
    faker: Faker, count: int, existing_accounts: set[str]
) -> list[dict]:
    users = []
    seen_usernames: set[str] = set()

    for _ in range(count):
        first = faker.first_name()
        last = faker.last_name()

        # Build a username: firstname.lastname + optional suffix to avoid collisions
        base_username = f"{first.lower()}.{last.lower()}"
        username = base_username
        suffix = 1
        while username in seen_usernames:
            username = f"{base_username}{suffix}"
            suffix += 1
        seen_usernames.add(username)

        balance = round(random.uniform(SEED_MIN_BALANCE, SEED_MAX_BALANCE), 2)

        users.append(
            {
                "username": username,
                "password": faker.password(
                    length=12, special_chars=True, digits=True, upper_case=True
                ),
                "account_number": generate_account_number(existing_accounts),
                "balance": balance,
                "is_admin": False,
                "profile_picture": None,
                "reset_pin": generate_reset_pin(),
                "bio": faker.sentence(nb_words=10),
                "is_suspended": False,
            }
        )

    return users


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    logger.info(
        "Connecting to database '%s' at %s:%s …",
        DB_CONFIG["dbname"],
        DB_CONFIG["host"],
        DB_CONFIG["port"],
    )

    try:
        conn = psycopg2.connect(**DB_CONFIG)
    except psycopg2.OperationalError as exc:
        logger.error("ERROR: Could not connect to the database.\n  %s", exc)
        sys.exit(1)

    conn.autocommit = False

    try:
        with conn.cursor() as cur:
            if SEED_CLEAR:
                logger.info("SEED_CLEAR=true — deleting all non-admin users …")
                cur.execute("DELETE FROM users WHERE is_admin = FALSE")
                logger.info("  Deleted %s user(s).", cur.rowcount)

            # Collect account numbers already in use so we never duplicate them
            cur.execute("SELECT account_number FROM users")
            existing_accounts: set[str] = {row[0] for row in cur.fetchall()}

            # Collect usernames already in use
            cur.execute("SELECT username FROM users")
            existing_usernames: set[str] = {row[0] for row in cur.fetchall()}

        logger.info("Generating %s fake user(s) with locale '%s' …", SEED_COUNT, SEED_LOCALE)
        faker = Faker(SEED_LOCALE)
        Faker.seed(0)  # reproducible output; remove or change for random results

        users = build_fake_users(faker, SEED_COUNT, existing_accounts)

        inserted = 0
        skipped = 0

        with conn.cursor() as cur:
            for user in users:
                if user["username"] in existing_usernames:
                    logger.info("  SKIP  %s (username already exists)", user["username"])
                    skipped += 1
                    continue

                cur.execute(
                    """
                    INSERT INTO users
                        (username, password, account_number, balance,
                         is_admin, profile_picture, reset_pin, bio, is_suspended)
                    VALUES
                        (%(username)s, %(password)s, %(account_number)s, %(balance)s,
                         %(is_admin)s, %(profile_picture)s, %(reset_pin)s, %(bio)s, %(is_suspended)s)
                    ON CONFLICT (username) DO NOTHING
                    """,
                    user,
                )
                if cur.rowcount:
                    logger.info(
                        "  INSERT %s  (acc: %s, balance: %.2f)",
                        user["username"],
                        user["account_number"],
                        user["balance"],
                    )
                    existing_usernames.add(user["username"])
                    inserted += 1
                else:
                    logger.info("  SKIP  %s (conflict on insert)", user["username"])
                    skipped += 1

        conn.commit()
        logger.info("\nDone. Inserted: %s, Skipped: %s", inserted, skipped)

    except Exception as exc:
        conn.rollback()
        logger.error("ERROR: %s", exc)
        sys.exit(1)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
