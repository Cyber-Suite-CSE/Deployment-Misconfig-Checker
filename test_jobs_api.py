#!/usr/bin/env python3
"""
Test the paginated jobs list endpoint
"""

import requests
import json
from datetime import datetime, timedelta

API_BASE_URL = "http://localhost:8000"


def test_jobs_endpoint():
    """Test the /api/jobs endpoint with various filters"""

    print("=" * 60)
    print("Testing Paginated Jobs Endpoint")
    print("=" * 60)

    # Test 1: Get all jobs (default pagination)
    print("\n1. GET /api/jobs (default)")
    response = requests.get(f"{API_BASE_URL}/api/jobs")
    print(f"   Status: {response.status_code}")
    print(f"   Total jobs: {response.json()['total']}")
    print(f"   Page: {response.json()['page']}/{response.json()['total_pages']}")

    # Test 2: Custom pagination
    print("\n2. GET /api/jobs?page=1&page_size=5")
    response = requests.get(f"{API_BASE_URL}/api/jobs?page=1&page_size=5")
    print(f"   Status: {response.status_code}")
    print(f"   Jobs returned: {len(response.json()['jobs'])}")
    print(f"   Total: {response.json()['total']}")
    print(f"   Total pages: {response.json()['total_pages']}")

    # Test 3: Filter by status
    print("\n3. GET /api/jobs?status=pending")
    response = requests.get(f"{API_BASE_URL}/api/jobs?status=pending")
    print(f"   Status: {response.status_code}")
    print(f"   Pending jobs: {response.json()['total']}")

    # Test 4: Filter by completed status
    print("\n4. GET /api/jobs?status=completed")
    response = requests.get(f"{API_BASE_URL}/api/jobs?status=completed")
    print(f"   Status: {response.status_code}")
    print(f"   Completed jobs: {response.json()['total']}")
    if response.json()["total"] > 0:
        job = response.json()["jobs"][0]
        print(f"   First job: {job['domain']} - {job['created_at']}")

    # Test 5: Domain search
    print("\n5. GET /api/jobs?domain_search=localhost")
    response = requests.get(f"{API_BASE_URL}/api/jobs?domain_search=localhost")
    print(f"   Status: {response.status_code}")
    print(f"   Jobs matching 'localhost': {response.json()['total']}")

    # Test 6: Date range filter
    today = datetime.utcnow()
    yesterday = today - timedelta(days=1)
    date_to = today.isoformat() + "Z"
    date_from = yesterday.isoformat() + "Z"

    print(f"\n6. GET /api/jobs?date_from={date_from}&date_to={date_to}")
    response = requests.get(
        f"{API_BASE_URL}/api/jobs?date_from={date_from}&date_to={date_to}"
    )
    print(f"   Status: {response.status_code}")
    print(f"   Jobs in date range: {response.json()['total']}")

    # Test 7: Combined filters
    print("\n7. GET /api/jobs?status=completed&domain_search=example")
    response = requests.get(
        f"{API_BASE_URL}/api/jobs?status=completed&domain_search=example"
    )
    print(f"   Status: {response.status_code}")
    print(f"   Completed jobs matching 'example': {response.json()['total']}")

    # Test 8: Invalid status (should fail)
    print("\n8. GET /api/jobs?status=invalid")
    response = requests.get(f"{API_BASE_URL}/api/jobs?status=invalid")
    print(f"   Status: {response.status_code} (expected 400)")
    if response.status_code == 400:
        print(f"   Error: {response.json()['detail']}")

    # Test 9: Page size validation (should be capped at 100)
    print("\n9. GET /api/jobs?page_size=200")
    response = requests.get(f"{API_BASE_URL}/api/jobs?page_size=200")
    print(f"   Status: {response.status_code}")
    print(f"   Page size used: {response.json()['page_size']} (should be 20 or 100)")

    print("\n" + "=" * 60)
    print("Test Complete!")
    print("=" * 60)


if __name__ == "__main__":
    try:
        test_jobs_endpoint()
    except requests.exceptions.ConnectionError:
        print("\nError: Could not connect to API. Is the server running?")
        print("Start the server with: uvicorn api:app --reload")
    except Exception as e:
        print(f"\nError: {e}")
