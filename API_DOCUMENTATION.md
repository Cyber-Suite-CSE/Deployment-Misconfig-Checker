# API Endpoint Documentation

## List Jobs (GET /api/jobs)

Retrieves a paginated list of all scan jobs with filtering and sorting capabilities.

### Endpoint

```
GET /api/jobs
```

### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `page` | integer | No | 1 | Page number (1-indexed, minimum: 1) |
| `page_size` | integer | No | 20 | Items per page (range: 1-100) |
| `status` | string | No | - | Filter by job status: `pending`, `running`, `completed`, `failed` |
| `domain_search` | string | No | - | Search domains by substring (case-insensitive) |
| `date_from` | string | No | - | Filter jobs created after this date (ISO 8601 format) |
| `date_to` | string | No | - | Filter jobs created before this date (ISO 8601 format) |

### Response Format

```json
{
  "jobs": [
    {
      "job_id": "550e8400-e29b-41d4-a716-446655440000",
      "domain": "example.com",
      "status": "completed",
      "created_at": "2024-02-12T10:30:45.123456Z",
      "has_results": true,
      "error": null
    }
  ],
  "total": 45,
  "page": 1,
  "page_size": 20,
  "total_pages": 3
}
```

### Response Fields

- `jobs` (array): List of job summaries
  - `job_id` (string): Unique identifier for the job
  - `domain` (string): Target domain that was scanned
  - `status` (string): Current job status (`pending`, `running`, `completed`, `failed`)
  - `created_at` (string): ISO 8601 timestamp when job was created
  - `has_results` (boolean): Whether the job has scan results available
  - `error` (string | null): Error message if job failed
- `total` (integer): Total number of jobs matching the filters
- `page` (integer): Current page number
- `page_size` (integer): Number of items per page
- `total_pages` (integer): Total number of pages

### Default Behavior

- Jobs are sorted by `created_at` in descending order (newest first)
- Default pagination: 20 items per page
- All jobs are returned if no filters are specified

### Error Responses

**400 Bad Request**
```json
{
  "detail": "Invalid status 'invalid'. Valid values: completed, failed, pending, running"
}
```

**400 Bad Request**
```json
{
  "detail": "Invalid date_from format: invalid-date. Use ISO 8601 format (e.g., 2024-01-01T00:00:00)"
}
```

## Example Usage

### 1. Get First Page (Default)

```bash
curl http://localhost:8003/api/jobs
```

### 2. Custom Pagination

```bash
curl "http://localhost:8003/api/jobs?page=2&page_size=10"
```

### 3. Filter by Status

```bash
curl "http://localhost:8003/api/jobs?status=completed"
curl "http://localhost:8003/api/jobs?status=running"
```

### 4. Search Domains

```bash
curl "http://localhost:8003/api/jobs?domain_search=example.com"
curl "http://localhost:8003/api/jobs?domain_search=localhost"
```

### 5. Date Range Filter

```bash
curl "http://localhost:8003/api/jobs?date_from=2024-01-01T00:00:00Z&date_to=2024-12-31T23:59:59Z"
```

### 6. Combined Filters

```bash
curl "http://localhost:8003/api/jobs?status=completed&domain_search=example&page=1&page_size=50"
```

### 7. Using Python requests

```python
import requests

response = requests.get("http://localhost:8003/api/jobs", params={
    "page": 1,
    "page_size": 20,
    "status": "completed"
})

data = response.json()
print(f"Total jobs: {data['total']}")
for job in data['jobs']:
    print(f"{job['domain']} - {job['status']} - {job['created_at']}")
```

### 8. Using JavaScript fetch

```javascript
fetch('http://localhost:8003/api/jobs?page=1&page_size=20&status=completed')
  .then(response => response.json())
  .then(data => {
    console.log(`Total jobs: ${data.total}`);
    data.jobs.forEach(job => {
      console.log(`${job.domain} - ${job.status} - ${job.created_at}`);
    });
  });
```

## Integration Notes

### Performance Considerations

- Use appropriate page sizes (default 20, max 100) to avoid large responses
- Apply filters to reduce the total number of jobs retrieved
- For large job lists, implement client-side caching

### Dashboard Integration

The response format is designed to work seamlessly with the Cyber-Suite-Dashboard:
- `has_results` field allows the UI to show which jobs have scan data available
- `status` field enables filtering and sorting in the UI
- Pagination metadata enables navigation controls
- ISO 8601 timestamps are easily parsed by JavaScript Date objects

### Related Endpoints

- `POST /api/scan` - Submit a new scan job
- `GET /api/status/{job_id}` - Get detailed status and results for a specific job
- `GET /api/health` - Health check endpoint
