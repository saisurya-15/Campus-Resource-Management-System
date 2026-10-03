# Campus Resource Management System

A lightweight local backend written in C++ with SQLite, `cpp-httplib`, and `nlohmann/json`. It provides a REST-style JSON API, stores records in SQLite, and includes a browser console for managing data.

The server listens on `127.0.0.1:12345` by default.

## Features

- REST-style CRUD API for JSON records
- Automatic table creation
- SQLite-based local persistence
- Built-in browser console
- API key and master key authentication
- CORS allowlist
- Table statistics and request counters
- Record ordering and pagination
- JSON import
- JSON and CSV export

## Tech Stack

- C++17
- SQLite
- `cpp-httplib`
- `nlohmann/json`

## Project Files

- `main.cpp` - HTTP server, authentication, CORS, and database logic
- `index.html` - browser console
- `example.html` - test client
- `sqlite3.c` / `sqlite3.h` - SQLite source
- `httplib.h` - HTTP server library
- `json.hpp` - JSON library
- `build.bat` - Windows build script
- `keys.json` - API key configuration
- `allow-origin.json` - CORS allowlist
- `data.db` - SQLite database

## Requirements

- Windows
- C++17-compatible compiler
- `gcc` and `g++`
- MinGW or compatible toolchain

## Build

### Windows

Use the included build script:

```bat
build.bat
```

Or build manually:

```bat
gcc -c sqlite3.c -o sqlite3.o
g++ -std=c++17 -pthread -o db_server.exe main.cpp sqlite3.o -lws2_32
```

## Run

Start the server:

```bat
db_server.exe
```

On startup, the server will:

- open or create `data.db`
- load `keys.json`, or generate new keys if the file does not exist
- load `allow-origin.json`
- print the browser URLs for API key and master key access

Open the printed URL in a browser to access the console.

## Authentication

The API accepts the key in the `X-LC-Key` header.

Two key types are supported:

- `api_key` - can read, create, and update records
- `master_key` - required for deletion and origin allowlist changes

The root console uses:

```text
/?apikey=YOUR_API_KEY
/?masterkey=YOUR_MASTER_KEY
```

Keep real keys private and do not commit them to a public repository.

## Data Model

Each class is stored in its own SQLite table with the following fields:

- `id` - auto-increment primary key
- `objectId` - unique record ID
- `createdAt` - timestamp
- `updatedAt` - timestamp
- `data` - JSON payload stored as text

Example:

```json
{
  "objectId": "1721890000000000-1",
  "createdAt": "2026-04-26T11:21:00Z",
  "updatedAt": "2026-04-26T11:21:00Z",
  "data": {
    "resourceName": "Computer Lab",
    "location": "Block A",
    "capacity": 60
  }
}
```

## API

### General

- `GET /` - browser console
- `GET /tables` - list tables
- `GET /stats` - table and request statistics
- `GET /origins` - list allowed origins
- `POST /origins` - add an origin
- `DELETE /origins?origin=http://example.com` - remove an origin

### Records

- `POST /classes/{className}` - create a record
- `GET /classes/{className}` - list records
- `GET /classes/{className}/{objectId}` - get a record
- `PUT /classes/{className}/{objectId}` - update a record
- `DELETE /classes/{className}/{objectId}` - delete a record

### Query Parameters

`GET /classes/{className}` supports:

- `order` - sort records
- `limit` - maximum number of records
- `skip` - row offset

Example:

```text
/classes/GameScore?order=-updatedAt&limit=10
```

## Web Console

The built-in console provides:

- table browsing
- record creation and editing
- record structure inspection
- usage statistics
- JSON import
- JSON export
- CSV export
- origin allowlist management

## CORS

- `http://localhost:*` and `http://127.0.0.1:*` are always allowed
- additional origins can be stored in `allow-origin.json`
- disallowed origins receive HTTP `403`

## Notes

- The server binds to `127.0.0.1` and is intended for local use.
- `data.db` is the local SQLite database.
- `keys.json` contains authentication keys and should be kept private.
- Additional security configuration is required for public deployment.
