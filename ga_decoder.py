#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "qrcode[pil]>=7.4.2",
# ]
# ///

"""
Google Authenticator Migration URL Decoder

This script decodes otpauth-migration:// URLs exported from Google Authenticator
and converts them to standard otpauth:// URLs with Base32-encoded secrets.
"""

import sys
import base64
import argparse
from urllib.parse import urlparse, parse_qs, quote
from typing import List, Dict, Any, Tuple, Optional
from io import BytesIO
from pathlib import Path


class ProtobufParser:
    """Simple protobuf wire format parser for Google Authenticator migration data."""

    # Wire types
    WIRETYPE_VARINT = 0
    WIRETYPE_FIXED64 = 1
    WIRETYPE_LENGTH_DELIMITED = 2
    WIRETYPE_START_GROUP = 3
    WIRETYPE_END_GROUP = 4
    WIRETYPE_FIXED32 = 5

    def __init__(self, data: bytes):
        self.stream = BytesIO(data)

    def read_varint(self) -> int:
        """Read a varint from the stream."""
        result = 0
        shift = 0
        while True:
            byte = self.stream.read(1)
            if not byte:
                raise ValueError("Unexpected end of stream while reading varint")
            b = byte[0]
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result
            shift += 7

    def read_tag(self) -> Tuple[int, int]:
        """Read a field tag and return (field_number, wire_type)."""
        tag = self.read_varint()
        wire_type = tag & 0x07
        field_number = tag >> 3
        return field_number, wire_type

    def read_length_delimited(self) -> bytes:
        """Read a length-delimited field."""
        length = self.read_varint()
        data = self.stream.read(length)
        if len(data) != length:
            raise ValueError(f"Expected {length} bytes, got {len(data)}")
        return data

    def skip_field(self, wire_type: int):
        """Skip a field based on its wire type."""
        if wire_type == self.WIRETYPE_VARINT:
            self.read_varint()
        elif wire_type == self.WIRETYPE_FIXED64:
            self.stream.read(8)
        elif wire_type == self.WIRETYPE_LENGTH_DELIMITED:
            self.read_length_delimited()
        elif wire_type == self.WIRETYPE_FIXED32:
            self.stream.read(4)
        else:
            raise ValueError(f"Unknown wire type: {wire_type}")

    def parse_otp_parameters(self, data: bytes) -> Dict[str, Any]:
        """Parse OTPParameters message."""
        parser = ProtobufParser(data)
        result = {
            'secret': b'',
            'name': '',
            'issuer': '',
            'algorithm': 1,  # Default SHA1
            'digits': 1,     # Default 6 digits
            'type': 2,       # Default TOTP
            'counter': 0
        }

        while parser.stream.tell() < len(data):
            try:
                field_num, wire_type = parser.read_tag()
            except ValueError:
                break

            if field_num == 1:  # secret
                result['secret'] = parser.read_length_delimited()
            elif field_num == 2:  # name
                result['name'] = parser.read_length_delimited().decode('utf-8', errors='replace')
            elif field_num == 3:  # issuer
                result['issuer'] = parser.read_length_delimited().decode('utf-8', errors='replace')
            elif field_num == 4:  # algorithm
                result['algorithm'] = parser.read_varint()
            elif field_num == 5:  # digits
                result['digits'] = parser.read_varint()
            elif field_num == 6:  # type
                result['type'] = parser.read_varint()
            elif field_num == 7:  # counter
                result['counter'] = parser.read_varint()
            else:
                parser.skip_field(wire_type)

        return result

    def parse_migration_payload(self) -> Dict[str, Any]:
        """Parse MigrationPayload message."""
        result = {
            'otp_parameters': [],
            'version': 0,
            'batch_size': 0,
            'batch_index': 0,
            'batch_id': 0
        }

        data_len = len(self.stream.getvalue())

        while self.stream.tell() < data_len:
            try:
                field_num, wire_type = self.read_tag()
            except ValueError:
                break

            if field_num == 1:  # otp_parameters (repeated)
                otp_data = self.read_length_delimited()
                otp_param = self.parse_otp_parameters(otp_data)
                result['otp_parameters'].append(otp_param)
            elif field_num == 2:  # version
                result['version'] = self.read_varint()
            elif field_num == 3:  # batch_size
                result['batch_size'] = self.read_varint()
            elif field_num == 4:  # batch_index
                result['batch_index'] = self.read_varint()
            elif field_num == 5:  # batch_id
                result['batch_id'] = self.read_varint()
            else:
                self.skip_field(wire_type)

        return result


def parse_migration_url(url: str) -> bytes:
    """
    Parse otpauth-migration:// URL and extract the base64-encoded data.

    Args:
        url: The migration URL from Google Authenticator

    Returns:
        Decoded protobuf binary data

    Raises:
        ValueError: If URL format is invalid
    """
    if not url.startswith("otpauth-migration://"):
        raise ValueError("URL must start with 'otpauth-migration://'")

    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    if "data" not in query_params:
        raise ValueError("URL must contain 'data' parameter")

    data_base64 = query_params["data"][0]

    try:
        # Decode base64 data
        decoded_data = base64.b64decode(data_base64)
        return decoded_data
    except Exception as e:
        raise ValueError(f"Failed to decode base64 data: {e}")


def get_algorithm_name(algorithm: int) -> str:
    """Convert algorithm enum to string name."""
    algorithms = {
        0: "SHA1",  # Default
        1: "SHA1",
        2: "SHA256",
        3: "SHA512",
        4: "MD5"
    }
    return algorithms.get(algorithm, "SHA1")


def get_digits_count(digits: int) -> int:
    """Convert digits enum to actual count."""
    digit_map = {
        0: 6,  # Default
        1: 6,
        2: 8
    }
    return digit_map.get(digits, 6)


def get_otp_type(otp_type: int) -> str:
    """Convert OTP type enum to string."""
    types = {
        0: "totp",  # Default
        1: "hotp",
        2: "totp"
    }
    return types.get(otp_type, "totp")


def generate_otpauth_url(account: Dict[str, Any]) -> str:
    """
    Generate a standard otpauth:// URL from account data.

    Args:
        account: Dictionary containing account information

    Returns:
        Standard otpauth:// URL string
    """
    otp_type = account["type"]
    name = account["name"]
    issuer = account["issuer"]
    secret = account["secret_base32"]
    algorithm = account["algorithm"]
    digits = account["digits"]

    # Build the label (issuer:name format)
    if issuer:
        label = f"{issuer}:{name}" if name else issuer
    else:
        label = name

    # URL encode the label
    encoded_label = quote(label)

    # Build query parameters
    params = [f"secret={secret}"]

    if issuer:
        params.append(f"issuer={quote(issuer)}")

    if algorithm != "SHA1":
        params.append(f"algorithm={algorithm}")

    if digits != 6:
        params.append(f"digits={digits}")

    if otp_type == "hotp":
        params.append(f"counter={account.get('counter', 0)}")

    query_string = "&".join(params)

    return f"otpauth://{otp_type}/{encoded_label}?{query_string}"


def decode_migration_data(binary_data: bytes) -> List[Dict[str, Any]]:
    """
    Decode the protobuf binary data and extract account information.

    Args:
        binary_data: Protobuf-encoded binary data

    Returns:
        List of account dictionaries
    """
    try:
        parser = ProtobufParser(binary_data)
        payload = parser.parse_migration_payload()
    except Exception as e:
        raise ValueError(f"Failed to parse protobuf data: {e}")

    accounts = []

    for otp_param in payload['otp_parameters']:
        # Convert secret bytes to base32
        secret_base32 = base64.b32encode(otp_param['secret']).decode('utf-8')

        account = {
            "name": otp_param['name'],
            "issuer": otp_param['issuer'],
            "secret_base32": secret_base32,
            "algorithm": get_algorithm_name(otp_param['algorithm']),
            "digits": get_digits_count(otp_param['digits']),
            "type": get_otp_type(otp_param['type']),
            "counter": otp_param['counter'] if otp_param['type'] == 1 else None
        }

        accounts.append(account)

    return accounts


def generate_qr_code(otpauth_url: str, output_path: Optional[Path] = None) -> Optional[str]:
    """
    Generate a QR code from an otpauth:// URL.

    Args:
        otpauth_url: The otpauth:// URL to encode
        output_path: Path to save the QR code image. If None, returns base64-encoded PNG.

    Returns:
        Path to saved file if output_path provided, otherwise base64-encoded PNG string
    """
    import qrcode
    from io import BytesIO

    # Create QR code instance
    qr = qrcode.QRCode(
        version=1,  # Auto-adjust size
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )

    qr.add_data(otpauth_url)
    qr.make(fit=True)

    # Create the QR code image
    img = qr.make_image(fill_color="black", back_color="white")

    if output_path:
        # Save to file
        img.save(output_path)
        return str(output_path)
    else:
        # Return base64-encoded PNG
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.read()).decode('utf-8')
        return img_base64


def sanitize_filename(name: str, issuer: str = "") -> str:
    """
    Create a safe filename from account name and issuer.

    Args:
        name: Account name
        issuer: Account issuer

    Returns:
        Sanitized filename
    """
    import re

    # Combine issuer and name
    if issuer:
        full_name = f"{issuer}_{name}" if name else issuer
    else:
        full_name = name or "account"

    # Remove or replace invalid characters
    safe_name = re.sub(r'[^\w\-_\. ]', '_', full_name)
    safe_name = re.sub(r'\s+', '_', safe_name)
    safe_name = safe_name.strip('_')

    return safe_name[:100]  # Limit length


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Decode Google Authenticator migration URLs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s "otpauth-migration://offline?data=..."
  %(prog)s --json "otpauth-migration://offline?data=..."
  %(prog)s --qr "otpauth-migration://offline?data=..."
  %(prog)s --qr --qr-dir ./my-qrcodes "otpauth-migration://offline?data=..."
        """
    )
    parser.add_argument(
        "url",
        help="The otpauth-migration:// URL from Google Authenticator"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format"
    )
    parser.add_argument(
        "--qr",
        action="store_true",
        help="Generate QR code images for each account"
    )
    parser.add_argument(
        "--qr-dir",
        type=Path,
        default=Path("qrcodes"),
        help="Directory to save QR code images (default: ./qrcodes)"
    )

    args = parser.parse_args()

    try:
        # Parse and decode the migration URL
        binary_data = parse_migration_url(args.url)
        accounts = decode_migration_data(binary_data)

        if not accounts:
            print("No accounts found in the migration data.", file=sys.stderr)
            return 1

        # Generate QR codes if requested
        qr_files = {}
        if args.qr:
            # Create output directory
            args.qr_dir.mkdir(parents=True, exist_ok=True)

            for i, account in enumerate(accounts, 1):
                otpauth_url = generate_otpauth_url(account)
                filename = sanitize_filename(account['name'], account['issuer'])
                qr_path = args.qr_dir / f"{filename}.png"

                # Handle duplicate filenames
                if qr_path.exists():
                    qr_path = args.qr_dir / f"{filename}_{i}.png"

                generate_qr_code(otpauth_url, qr_path)
                qr_files[i] = qr_path

            print(f"\nGenerated {len(qr_files)} QR code(s) in: {args.qr_dir.absolute()}")

        if args.json:
            import json
            output = []
            for i, account in enumerate(accounts, 1):
                entry = {
                    **account,
                    "otpauth_url": generate_otpauth_url(account)
                }
                if i in qr_files:
                    entry["qr_code_path"] = str(qr_files[i])
                output.append(entry)
            print(json.dumps(output, indent=2, ensure_ascii=False))
        else:
            # Pretty print the results
            print(f"\n{'='*80}")
            print(f"Found {len(accounts)} account(s):")
            print(f"{'='*80}\n")

            for i, account in enumerate(accounts, 1):
                print(f"Account #{i}")
                print(f"  Name:      {account['name']}")
                print(f"  Issuer:    {account['issuer'] or 'N/A'}")
                print(f"  Type:      {account['type'].upper()}")
                print(f"  Algorithm: {account['algorithm']}")
                print(f"  Digits:    {account['digits']}")
                print(f"  Secret:    {account['secret_base32']}")

                if account['counter'] is not None:
                    print(f"  Counter:   {account['counter']}")

                otpauth_url = generate_otpauth_url(account)
                print(f"  URL:       {otpauth_url}")

                if i in qr_files:
                    print(f"  QR Code:   {qr_files[i]}")

                print()

        return 0

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
