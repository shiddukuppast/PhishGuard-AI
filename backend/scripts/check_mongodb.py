#!/usr/bin/env python3
"""
PhishGuard AI - MongoDB Atlas Diagnostic Utility
Validates database connectivity, TLS negotiation, authentication,
and collection access without exposing sensitive credentials.
"""

import sys
import os
import asyncio
import urllib.request
from typing import Optional, Tuple

# Ensure backend root is in Python module search path
backend_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

import certifi
import dns.resolver
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import (
    ConfigurationError,
    OperationFailure,
    ServerSelectionTimeoutError,
    NetworkTimeout,
    PyMongoError,
)
from app.config.settings import settings


def get_current_public_ip() -> str:
    """Fetch current outbound public IP address to aid in Atlas IP whitelisting."""
    endpoints = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com",
    ]
    for url in endpoints:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "PhishGuard-Diag/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                ip = resp.read().decode("utf-8").strip()
                if ip:
                    return ip
        except Exception:
            continue
    return "Unknown (could not query public IP)"


def mask_mongodb_uri(uri: str) -> str:
    """Mask password and user info in MongoDB connection string for safe display."""
    if not uri:
        return "<EMPTY>"
    try:
        scheme, rest = uri.split("://", 1)
        if "@" in rest:
            user_info, host_info = rest.split("@", 1)
            username = user_info.split(":")[0] if ":" in user_info else user_info
            return f"{scheme}://{username}:****@{host_info}"
        return f"{scheme}://{rest}"
    except Exception:
        return "<REDACTED URI>"


def extract_cluster_host(uri: str) -> Optional[str]:
    """Extract cluster host or first shard host from URI."""
    try:
        rest = uri.split("://", 1)[1]
        host_part = rest.split("@", 1)[-1].split("/", 1)[0].split("?", 1)[0]
        return host_part.split(",")[0].split(":")[0]
    except Exception:
        return None


def test_dns_resolution(cluster_host: str, is_srv: bool) -> Tuple[bool, str]:
    """Test DNS resolution for Atlas cluster or shard."""
    if not cluster_host:
        return False, "Could not extract host from URI"

    try:
        if is_srv:
            srv_target = f"_mongodb._tcp.{cluster_host}"
            answers = dns.resolver.resolve(srv_target, "SRV", lifetime=4.0)
            shards = [str(r.target).rstrip(".") for r in answers]
            return True, f"SRV lookup resolved {len(shards)} shard(s): {', '.join(shards[:3])}"
        else:
            answers = dns.resolver.resolve(cluster_host, "A", lifetime=4.0)
            ips = [str(r) for r in answers]
            return True, f"A record resolved: {', '.join(ips)}"
    except Exception as exc:
        return False, f"DNS resolution failed for {cluster_host}: {type(exc).__name__} ({exc})"


async def run_diagnostics():
    print("=" * 72)
    print("  PHISHGUARD AI - MONGODB ATLAS CONNECTIVITY DIAGNOSTICS")
    print("=" * 72)

    # 1. Environment & URI Check
    uri = settings.MONGODB_URI.strip()
    if not uri:
        print("\n[FAIL] MONGODB_URI is not set in environment or backend/.env.")
        print("Remediation: Set MONGODB_URI in backend/.env with your MongoDB Atlas connection string.")
        return 1

    masked_uri = mask_mongodb_uri(uri)
    is_srv = uri.startswith("mongodb+srv://")
    cluster_host = extract_cluster_host(uri)
    public_ip = get_current_public_ip()

    print(f"\n1. Environment Configuration:")
    print(f"   - Target Database  : {settings.DATABASE_NAME}")
    print(f"   - URI Format       : {'mongodb+srv (Standard SRV)' if is_srv else 'mongodb (Standard Replica Set)'}")
    print(f"   - Masked URI       : {masked_uri}")
    print(f"   - Current Public IP: {public_ip}")
    print(f"   - Root CA Bundle   : {certifi.where()}")

    # 2. DNS Verification
    print(f"\n2. DNS Resolution Test:")
    dns_ok, dns_msg = test_dns_resolution(cluster_host, is_srv)
    if dns_ok:
        print(f"   [PASS] {dns_msg}")
    else:
        print(f"   [WARN] {dns_msg}")
        print("   Notice: DNS resolution issues may indicate network restrictions, VPN interference, or custom DNS blockage.")

    # 3. Connection & TLS Handshake
    print(f"\n3. Connection & Ping Handshake:")
    client = None
    try:
        client = AsyncIOMotorClient(
            uri,
            tlsCAFile=certifi.where(),
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
        )

        print("   Initiating cluster admin ping (5s timeout)...")
        ping_res = await client.admin.command("ping")
        print(f"   [PASS] Cluster ping successful! Response: {ping_res}")

        # 4. Database Access
        db = client[settings.DATABASE_NAME]
        print(f"\n4. Database & Collections Access ({settings.DATABASE_NAME}):")
        
        collections = await db.list_collection_names()
        print(f"   - Existing collections: {collections if collections else '[] (Database is empty/new)'}")

        for col_name in ["users", "scans", "reports"]:
            count = await db[col_name].count_documents({})
            print(f"   - Collection '{col_name}': {count} documents")

        print("\n" + "=" * 72)
        print("  DIAGNOSTIC RESULT: ALL MONGODB CONNECTIVITY CHECKS PASSED")
        print("=" * 72)
        return 0

    except Exception as exc:
        err_type = type(exc).__name__
        err_str = str(exc)
        print(f"\n   [FAIL] Connection attempt failed: {err_type}")
        print(f"   Error details: {err_str[:400]}")

        print("\n" + "=" * 72)
        print("  ROOT CAUSE ANALYSIS & ACTIONABLE REMEDIATION:")
        print("=" * 72)

        # Categorize Error
        if "tlsv1 alert internal error" in err_str.lower() or "tls" in err_str.lower() and "internal error" in err_str.lower():
            print("\n[CATEGORY]: TLS HANDSHAKE REJECTED BY ATLAS (IP ACCESS LIST RESTRICTION)")
            print("\nExplanation:")
            print("  MongoDB Atlas edge proxies reject incoming TLS handshakes with")
            print("  'TLSV1_ALERT_INTERNAL_ERROR' when the connecting IP address is not")
            print("  whitelisted in the Atlas Project Network Access IP Access List.")
            print(f"\nAction Required:")
            print(f"  1. Log in to your MongoDB Atlas dashboard: https://cloud.mongodb.com")
            print(f"  2. In the left navigation, under 'Security', click 'Network Access'.")
            print(f"  3. Click 'Add IP Address'.")
            print(f"  4. Add your current public IP address:")
            print(f"       -> IP: {public_ip}/32 (Comment: PhishGuard Dev Host)")
            print(f"     (Or for local development convenience, add '0.0.0.0/0' to allow access from any IP).")
            print(f"  5. Click 'Confirm' and wait 1-2 minutes for Atlas to propagate the rule.")
            print(f"  6. Rerun this diagnostic script: python backend/scripts/check_mongodb.py")

        elif isinstance(exc, OperationFailure) or "auth" in err_str.lower() or "authentication" in err_str.lower():
            print("\n[CATEGORY]: MONGODB AUTHENTICATION FAILURE")
            print("\nExplanation:")
            print("  The database user credentials specified in MONGODB_URI were rejected by Atlas.")
            print("\nAction Required:")
            print("  1. In Atlas console, go to 'Security' -> 'Database Access'.")
            print("  2. Verify that your database user exists with 'Read and write to any database' permission.")
            print("  3. If your password contains special characters (: / ? # [ ] @ %), ensure they are URL-encoded.")
            print("  4. Update MONGODB_URI in backend/.env.")

        elif isinstance(exc, ConfigurationError) or "empty host" in err_str.lower():
            print("\n[CATEGORY]: URI CONFIGURATION ERROR")
            print("\nExplanation:")
            print("  The MONGODB_URI syntax is malformed or missing required host parameters.")
            print("\nAction Required:")
            print("  Use the standard Atlas SRV URI format:")
            print("  mongodb+srv://<username>:<password>@cluster0.<cluster_id>.mongodb.net/phishguard?retryWrites=true&w=majority")

        elif isinstance(exc, ServerSelectionTimeoutError) or isinstance(exc, NetworkTimeout):
            print("\n[CATEGORY]: SERVER SELECTION TIMEOUT / NETWORK REACHABILITY FAILURE")
            print("\nExplanation:")
            print("  The client could not reach any replica set members within 5 seconds.")
            print("  This typically occurs when a firewall blocks outbound TCP port 27017,")
            print("  an active VPN routes traffic away, or Atlas Network Access rejects the IP.")
            print(f"\nAction Required:")
            print(f"  1. Ensure outbound TCP traffic on port 27017 is allowed on your network.")
            print(f"  2. Add your current public IP ({public_ip}) to Atlas Network Access.")
            print(f"  3. Check if your Atlas cluster is paused or in an error state in cloud.mongodb.com.")

        else:
            print(f"\n[CATEGORY]: UNHANDLED EXCEPTION ({err_type})")
            print("  Inspect backend logs and network routing.")

        return 1

    finally:
        if client:
            client.close()


if __name__ == "__main__":
    exit_code = asyncio.run(run_diagnostics())
    sys.exit(exit_code)

