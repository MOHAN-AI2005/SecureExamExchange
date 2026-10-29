import argparse
import base64
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

RSA_BITS = 3072
AES_KEY_BYTES = 32       # AES-256
NONCE_BYTES = 12         # 96-bit GCM nonce
TAG_BYTES = 16           # 128-bit GCM tag
VERSION = 1


class ExchangeError(Exception):
    """Safe, user-facing exchange failure."""


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(value):
    if not isinstance(value, str):
        raise ValueError("Expected a Base64 string")
    return base64.b64decode(value, validate=True)


def canonical_json(obj):
    """Deterministic JSON representation for signing and AAD."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def save_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExchangeError("Cannot read a valid package file.") from exc


def load_private(path, password):
    try:
        key = load_pem_private_key(
            Path(path).read_bytes(),
            password=password.encode("utf-8"),
        )
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ExchangeError("The private key is not RSA.")
        return key
    except ExchangeError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise ExchangeError(
            "Cannot load private key. Check the path and password."
        ) from exc


def load_public(path):
    try:
        key = load_pem_public_key(Path(path).read_bytes())
        if not isinstance(key, rsa.RSAPublicKey):
            raise ExchangeError("The public key is not RSA.")
        return key
    except ExchangeError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise ExchangeError("Cannot load the required public key.") from exc


def generate_keypair(private_path, public_path):
    """Generate RSA-3072 keys and encrypt the private-key file at rest."""
    private_path = Path(private_path)
    public_path = Path(public_path)

    if private_path.exists() or public_path.exists():
        raise ExchangeError(
            "A key file already exists. Refusing to overwrite keys."
        )

    password = getpass("Private-key password (use a strong password): ")
    confirm = getpass("Confirm password: ")

    if len(password) < 12:
        raise ExchangeError("Use a password of at least 12 characters.")
    if password != confirm:
        raise ExchangeError("Passwords do not match.")

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_BITS,
    )

    private_bytes = key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        BestAvailableEncryption(password.encode("utf-8")),
    )
    public_bytes = key.public_key().public_bytes(
        Encoding.PEM,
        PublicFormat.SubjectPublicKeyInfo,
    )

    # Exclusive creation prevents accidental replacement of existing keys.
    for path in (private_path, public_path):
        path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with private_path.open("xb") as f:
            f.write(private_bytes)
        with public_path.open("xb") as f:
            f.write(public_bytes)
    except OSError as exc:
        # Do not leave a partial key pair that could be mistaken as complete.
        for path in (private_path, public_path):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise ExchangeError("Could not safely save the key pair.") from exc

    # Restrict permissions where the operating system supports POSIX modes.
    if os.name == "posix":
        private_path.chmod(0o600)

    print(f"RSA-{RSA_BITS} key pair generated.")
    print(f"Private key: {private_path}")
    print(f"Public key:  {public_path}")
    print("Keep the private key secret and exchange only public keys.")


def make_payload(source_file, recipient_public_key):
    """Encrypt a file and return the complete signed payload fields."""
    source_file = Path(source_file)

    if not source_file.is_file():
        raise ExchangeError("The input examination paper does not exist.")

    plaintext = source_file.read_bytes()

    # The basename prevents a received package from choosing an output path.
    metadata = {
        "version": VERSION,
        "algorithm": "AES-256-GCM",
        "key_wrap": "RSA-OAEP-SHA256",
        "signature": "RSA-PSS-SHA256",
        "filename": source_file.name,
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }

    # Each encryption gets a fresh AES key and nonce.
    session_key = secrets.token_bytes(AES_KEY_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)

    # Bind metadata to the authenticated encryption.
    aad = canonical_json(metadata)
    encrypted = AESGCM(session_key).encrypt(nonce, plaintext, aad)
    ciphertext, tag = encrypted[:-TAG_BYTES], encrypted[-TAG_BYTES:]

    wrapped_key = recipient_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "metadata": metadata,
        "encrypted_key": b64(wrapped_key),
        "nonce": b64(nonce),
        "ciphertext": b64(ciphertext),
        "tag": b64(tag),
    }


def encrypt_file(source, output, sender_private_key, recipient_public_key):
    payload = make_payload(source, recipient_public_key)

    signature = sender_private_key.sign(
        canonical_json(payload),
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    package = {
        "payload": payload,
        "signature": b64(signature),
    }
    save_json(output, package)
    print(f"Encrypted and signed package saved: {output}")


def verify_and_decrypt(package, sender_public_key, recipient_private_key):
    """
    Return plaintext bytes only after signature and GCM checks both pass.
    This function never writes plaintext to disk.
    """
    try:
        if not isinstance(package, dict) or set(package) != {
            "payload", "signature"
        }:
            raise ExchangeError("Invalid package structure.")

        payload = package["payload"]
        if not isinstance(payload, dict) or set(payload) != {
            "metadata", "encrypted_key", "nonce", "ciphertext", "tag"
        }:
            raise ExchangeError("Invalid package payload structure.")

        metadata = payload["metadata"]
        if not isinstance(metadata, dict) or set(metadata) != {
            "version", "algorithm", "key_wrap", "signature",
            "filename", "created_utc"
        }:
            raise ExchangeError("Invalid metadata.")

        expected_metadata = {
            "version": VERSION,
            "algorithm": "AES-256-GCM",
            "key_wrap": "RSA-OAEP-SHA256",
            "signature": "RSA-PSS-SHA256",
        }
        for name, expected in expected_metadata.items():
            if metadata.get(name) != expected:
                raise ExchangeError("Unsupported or invalid metadata.")

        if not isinstance(metadata["filename"], str):
            raise ExchangeError("Invalid filename metadata.")
        if (not metadata["filename"]
                or metadata["filename"] in {".", ".."}
                or Path(metadata["filename"]).name != metadata["filename"]
                or "/" in metadata["filename"]
                or "\\" in metadata["filename"]):
            raise ExchangeError("Unsafe filename in package.")

        # Verify the sender before attempting private-key decryption.
        signature = unb64(package["signature"])
        sender_public_key.verify(
            signature,
            canonical_json(payload),
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        nonce = unb64(payload["nonce"])
        ciphertext = unb64(payload["ciphertext"])
        tag = unb64(payload["tag"])
        encrypted_key = unb64(payload["encrypted_key"])

        if len(nonce) != NONCE_BYTES:
            raise ExchangeError("Invalid GCM nonce length.")
        if len(tag) != TAG_BYTES:
            raise ExchangeError("Invalid GCM authentication-tag length.")

        # Recover the AES session key using the recipient's private key.
        session_key = recipient_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        if len(session_key) != AES_KEY_BYTES:
            raise ExchangeError("Invalid AES session key length.")

        # GCM raises InvalidTag if the ciphertext, tag, nonce, or AAD
        # does not authenticate. No file has been written at this point.
        plaintext = AESGCM(session_key).decrypt(
            nonce,
            ciphertext + tag,
            canonical_json(metadata),
        )
        return plaintext

    except ExchangeError:
        raise
    except InvalidSignature as exc:
        raise ExchangeError(
            "Signature verification failed. Package rejected."
        ) from exc
    except InvalidTag as exc:
        raise ExchangeError(
            "AES-GCM authentication failed. No file released."
        ) from exc
    except (ValueError, TypeError, KeyError, OSError) as exc:
        raise ExchangeError(
            "Invalid package or cryptographic operation failed."
        ) from exc


def decrypt_file(package_path, output_dir, sender_public_key,
                 recipient_private_key):
    package = load_json(package_path)
    plaintext = verify_and_decrypt(
        package, sender_public_key, recipient_private_key
    )

    # Create the destination only after both security checks succeed.
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / package["payload"]["metadata"]["filename"]

    # Exclusive creation avoids silently overwriting an existing paper.
    try:
        with output_path.open("xb") as f:
            f.write(plaintext)
    except FileExistsError as exc:
        raise ExchangeError(
            "Output file already exists. Choose another output directory."
        ) from exc
    except OSError as exc:
        raise ExchangeError("Could not safely save the recovered file.") from exc

    print("SUCCESS: Signature and AES-GCM authentication verified.")
    print(f"Recovered examination paper: {output_path}")


def run_selftest():
    """Demonstrate successful recovery and all required rejection cases."""
    with tempfile.TemporaryDirectory(prefix="secure_exam_test_") as temp:
        root = Path(temp)
        original = b"CONFIDENTIAL EXAMINATION PAPER\nQuestion 1: Explain RSA.\n"

        def new_key():
            return rsa.generate_private_key(
                public_exponent=65537, key_size=RSA_BITS
            )

        sender = new_key()
        recipient = new_key()
        wrong_sender = new_key()
        wrong_recipient = new_key()

        def package_for(data):
            src = root / "input.txt"
            src.write_bytes(data)
            payload = make_payload(src, recipient.public_key())
            sig = sender.sign(
                canonical_json(payload),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return {"payload": payload, "signature": b64(sig)}

        def expect_rejection(label, pkg, pub, priv):
            try:
                verify_and_decrypt(pkg, pub, priv)
            except ExchangeError as exc:
                print(f"PASS - {label}: rejected ({exc})")
            else:
                raise AssertionError(f"FAIL - {label}: package accepted")

        first = package_for(original)
        recovered = verify_and_decrypt(
            first, sender.public_key(), recipient
        )
        assert recovered == original
        print("PASS - Authorized recipient recovered the original file.")

        # Ciphertext tampering, even with the original signature, is rejected.
        tampered = json.loads(json.dumps(first))
        raw = bytearray(unb64(tampered["payload"]["ciphertext"]))
        if raw:
            raw[0] ^= 1
        else:
            raw.append(1)
        tampered["payload"]["ciphertext"] = b64(bytes(raw))
        expect_rejection("Modified ciphertext", tampered,
                         sender.public_key(), recipient)

        tampered = json.loads(json.dumps(first))
        tampered["payload"]["metadata"]["filename"] = "attacker.txt"
        expect_rejection("Modified metadata", tampered,
                         sender.public_key(), recipient)

        tampered = json.loads(json.dumps(first))
        sig = bytearray(unb64(tampered["signature"]))
        sig[0] ^= 1
        tampered["signature"] = b64(bytes(sig))
        expect_rejection("Modified signature", tampered,
                         sender.public_key(), recipient)

        # Test GCM independently: alter ciphertext, then create a valid
        # sender signature over the altered package.
        gcm_tampered = json.loads(json.dumps(first))
        raw = bytearray(
            unb64(gcm_tampered["payload"]["ciphertext"])
        )

        if raw:
            raw[0] ^= 1
        else:
            raw.append(1)

        gcm_tampered["payload"]["ciphertext"] = b64(bytes(raw))

        # Re-sign with the legitimate sender key so RSA-PSS verification
        # succeeds and the test reaches AES-GCM authentication.
        gcm_tampered["signature"] = b64(
            sender.sign(
                canonical_json(gcm_tampered["payload"]),
                padding.PSS(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        )

        try:
            verify_and_decrypt(
                gcm_tampered, sender.public_key(), recipient
            )
        except ExchangeError as exc:
            if str(exc) != "AES-GCM authentication failed. No file released.":
                raise AssertionError(
                    f"GCM test failed at an unexpected stage: {exc}"
                ) from exc

            print(
                "PASS - AES-GCM rejects corrupted ciphertext "
                "after valid signature verification."
            )
        else:
            raise AssertionError(
                "FAIL - AES-GCM accepted corrupted ciphertext"
            )

        expect_rejection("Incorrect recipient private key", first,
                         sender.public_key(), wrong_recipient)

        expect_rejection("Incorrect sender public key", first,
                         wrong_sender.public_key(), recipient)

        second = package_for(original)
        assert canonical_json(first) != canonical_json(second)
        assert first["payload"]["nonce"] != second["payload"]["nonce"]
        assert first["payload"]["encrypted_key"] != second["payload"]["encrypted_key"]
        print("PASS - Encrypting the same file twice produces different packages.")

        print("\nAll self-tests passed.")


def main():
    parser = argparse.ArgumentParser(
        description="Secure examination-paper exchange"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("keygen", help="Generate an RSA key pair")
    keygen.add_argument("--private", required=True)
    keygen.add_argument("--public", required=True)

    enc = commands.add_parser("encrypt", help="Encrypt and sign a file")
    enc.add_argument("--input", required=True)
    enc.add_argument("--output", required=True)
    enc.add_argument("--sender-private", required=True)
    enc.add_argument("--recipient-public", required=True)

    dec = commands.add_parser("decrypt", help="Verify and decrypt a package")
    dec.add_argument("--package", required=True)
    dec.add_argument("--output-dir", required=True)
    dec.add_argument("--sender-public", required=True)
    dec.add_argument("--recipient-private", required=True)

    commands.add_parser("selftest", help="Run security demonstration tests")
    args = parser.parse_args()

    try:
        if args.command == "keygen":
            generate_keypair(args.private, args.public)

        elif args.command == "encrypt":
            sender = load_private(
                args.sender_private,
                getpass("Sender private-key password: "),
            )
            recipient = load_public(args.recipient_public)
            encrypt_file(
                args.input, args.output, sender, recipient
            )

        elif args.command == "decrypt":
            sender = load_public(args.sender_public)
            recipient = load_private(
                args.recipient_private,
                getpass("Recipient private-key password: "),
            )
            decrypt_file(
                args.package, args.output_dir, sender, recipient
            )

        elif args.command == "selftest":
            run_selftest()

    except ExchangeError as exc:
        print(f"ERROR: {exc}")
        raise SystemExit(1)
    except (InvalidSignature, InvalidTag, ValueError, TypeError) as exc:
        # Do not expose plaintext or detailed cryptographic internals.
        print(f"ERROR: Operation rejected ({type(exc).__name__}).")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
