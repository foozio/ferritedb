# FerriteDB SDK Guide

This guide covers the official SDKs and client libraries for FerriteDB, helping you integrate FerriteDB into your applications quickly and efficiently.

## Table of Contents

- [Available SDKs](#available-sdks)
- [JavaScript/TypeScript SDK](#javascripttypescript-sdk)
- [Rust SDK](#rust-sdk)
- [Python SDK](#python-sdk)
- [Go SDK](#go-sdk)
- [Authentication](#authentication)
- [Collections Management](#collections-management)
- [Records Operations](#records-operations)
- [File Management](#file-management)
- [Real-time Features](#real-time-features)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)

## Available SDKs

| Language | Package | Status | Documentation |
|----------|---------|--------|---------------|
| JavaScript/TypeScript | `@ferritedb/sdk-js` | ✅ Stable | [NPM](https://npmjs.com/package/@ferritedb/sdk-js) |
| Rust | `ferritedb-sdk` | ✅ Stable | [Crates.io](https://crates.io/crates/ferritedb-sdk) |
| Python | `ferritedb-python` | 🚧 Beta | [PyPI](https://pypi.org/project/ferritedb-python/) |
| Go | `ferritedb-go` | 🚧 Beta | [GitHub](https://github.com/ferritedb/ferritedb-go) |
| PHP | `ferritedb/php-sdk` | 📋 Planned | - |
| C# | `FerriteDB.SDK` | 📋 Planned | - |

## JavaScript/TypeScript SDK

### Installation

```bash
# npm
npm install @ferritedb/sdk-js

# yarn
yarn add @ferritedb/sdk-js

# pnpm
pnpm add @ferritedb/sdk-js
```

### Basic Setup

```typescript
import { FerriteDB } from '@ferritedb/sdk-js';

// Initialize client
const client = new FerriteDB({
  url: 'https://your-ferritedb-instance.com',
  // Optional: API key for server-to-server auth
  apiKey: 'your-api-key'
});

// Or with custom configuration
const client = new FerriteDB({
  url: 'https://your-ferritedb-instance.com',
  timeout: 10000,
  retries: 3,
  headers: {
    'X-Custom-Header': 'value'
  }
});
```

### Authentication

```typescript
// Register new user
const { user, token } = await client.auth.register({
  email: 'user@example.com',
  password: 'securepassword',
  passwordConfirm: 'securepassword'
});

// Login
const { user, token } = await client.auth.login({
  email: 'user@example.com',
  password: 'securepassword'
});

// Set auth token for subsequent requests
client.setAuthToken(token);

// Get current user
const currentUser = await client.auth.me();

// Refresh token
const { token: newToken } = await client.auth.refresh(refreshToken);

// Logout
await client.auth.logout();
```

### Collections

```typescript
// List collections
const collections = await client.collections.list();

// Get collection
const collection = await client.collections.get('posts');

// Create collection
const newCollection = await client.collections.create({
  name: 'posts',
  type: 'base',
  schema: {
    fields: [
      {
        name: 'title',
        type: 'text',
        required: true,
        options: { maxLength: 200 }
      },
      {
        name: 'content',
        type: 'text',
        required: false
      },
      {
        name: 'published',
        type: 'boolean',
        required: true,
        default: false
      }
    ]
  },
  rules: {
    list: 'user.role == "admin" || record.published == true',
    view: 'user.role == "admin" || record.published == true',
    create: 'user.role == "admin" || user.role == "user"',
    update: 'user.role == "admin" || record.author == user.id',
    delete: 'user.role == "admin" || record.author == user.id'
  }
});

// Update collection
const updatedCollection = await client.collections.update('posts', {
  schema: {
    fields: [
      {
        name: 'tags',
        type: 'text',
        required: false,
        options: { isArray: true }
      }
    ]
  }
});

// Delete collection
await client.collections.delete('posts');
```

### Records

```typescript
// Get collection reference
const posts = client.collection('posts');

// List records
const records = await posts.list({
  page: 1,
  perPage: 20,
  sort: '-created_at',
  filter: 'published = true',
  fields: 'id,title,author'
});

// Get single record
const record = await posts.get('record_id');

// Create record
const newRecord = await posts.create({
  title: 'My New Post',
  content: 'This is the content of my post.',
  published: false,
  author: 'user_id'
});

// Update record
const updatedRecord = await posts.update('record_id', {
  title: 'Updated Title',
  published: true
});

// Delete record
await posts.delete('record_id');

// Batch operations
const batchResults = await posts.batch([
  { action: 'create', data: { title: 'Post 1', content: 'Content 1' } },
  { action: 'create', data: { title: 'Post 2', content: 'Content 2' } },
  { action: 'update', id: 'existing_id', data: { published: true } }
]);
```

### File Management

```typescript
// Upload file
const file = await client.files.upload({
  file: fileBlob, // File object or Blob
  collection: 'posts',
  recordId: 'record_id',
  field: 'featured_image'
});

// Get file info
const fileInfo = await client.files.get('file_id');

// Download file
const fileBlob = await client.files.download('file_id');

// Delete file
await client.files.delete('file_id');

// List files
const files = await client.files.list({
  collection: 'posts',
  recordId: 'record_id'
});
```

### Real-time Subscriptions

```typescript
// Subscribe to collection changes
const unsubscribe = client.realtime.subscribe('posts', (event) => {
  switch (event.type) {
    case 'record_created':
      console.log('New post created:', event.record);
      break;
    case 'record_updated':
      console.log('Post updated:', event.record);
      break;
    case 'record_deleted':
      console.log('Post deleted:', event.recordId);
      break;
  }
});

// Subscribe with filter
const unsubscribe = client.realtime.subscribe('posts', (event) => {
  // Handle event
}, {
  filter: 'published = true'
});

// Unsubscribe
unsubscribe();

// Connection events
client.realtime.on('connect', () => {
  console.log('Connected to real-time server');
});

client.realtime.on('disconnect', () => {
  console.log('Disconnected from real-time server');
});

client.realtime.on('error', (error) => {
  console.error('Real-time error:', error);
});
```

### React Integration

```tsx
import React, { useEffect, useState } from 'react';
import { FerriteDB } from '@ferritedb/sdk-js';

// Custom hook for FerriteDB
function useFerriteDB() {
  const [client] = useState(() => new FerriteDB({
    url: process.env.REACT_APP_FERRITEDB_URL
  }));

  return client;
}

// Component example
function PostsList() {
  const client = useFerriteDB();
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchPosts() {
      try {
        const records = await client.collection('posts').list({
          filter: 'published = true',
          sort: '-created_at'
        });
        setPosts(records.records);
      } catch (error) {
        console.error('Failed to fetch posts:', error);
      } finally {
        setLoading(false);
      }
    }

    fetchPosts();

    // Subscribe to real-time updates
    const unsubscribe = client.realtime.subscribe('posts', (event) => {
      if (event.type === 'record_created' && event.record.published) {
        setPosts(prev => [event.record, ...prev]);
      } else if (event.type === 'record_updated') {
        setPosts(prev => prev.map(post => 
          post.id === event.record.id ? event.record : post
        ));
      } else if (event.type === 'record_deleted') {
        setPosts(prev => prev.filter(post => post.id !== event.recordId));
      }
    });

    return unsubscribe;
  }, [client]);

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      {posts.map(post => (
        <article key={post.id}>
          <h2>{post.title}</h2>
          <p>{post.content}</p>
        </article>
      ))}
    </div>
  );
}
```

## Rust SDK

### Installation

```toml
# Cargo.toml
[dependencies]
ferritedb-sdk = "0.1.0"
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
```

### Basic Setup

```rust
use ferritedb_sdk::{FerriteDB, Error};
use serde::{Deserialize, Serialize};

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Initialize client
    let client = FerriteDB::new("https://your-ferritedb-instance.com")
        .with_timeout(std::time::Duration::from_secs(30));

    // With API key
    let client = FerriteDB::new("https://your-ferritedb-instance.com")
        .with_api_key("your-api-key");

    Ok(())
}
```

### Authentication

```rust
use ferritedb_sdk::auth::{LoginRequest, RegisterRequest};

// Register
let register_req = RegisterRequest {
    email: "user@example.com".to_string(),
    password: "securepassword".to_string(),
    password_confirm: "securepassword".to_string(),
};

let auth_result = client.auth().register(register_req).await?;
println!("User registered: {}", auth_result.user.email);

// Login
let login_req = LoginRequest {
    email: "user@example.com".to_string(),
    password: "securepassword".to_string(),
};

let auth_result = client.auth().login(login_req).await?;
client.set_auth_token(&auth_result.token);

// Get current user
let current_user = client.auth().me().await?;
```

### Collections and Records

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Post {
    id: Option<String>,
    title: String,
    content: String,
    published: bool,
    author: String,
    created_at: Option<String>,
    updated_at: Option<String>,
}

// Create record
let new_post = Post {
    id: None,
    title: "My Rust Post".to_string(),
    content: "Content written in Rust!".to_string(),
    published: false,
    author: "user_id".to_string(),
    created_at: None,
    updated_at: None,
};

let created_post: Post = client
    .collection("posts")
    .create(new_post)
    .await?;

// List records
let posts: Vec<Post> = client
    .collection("posts")
    .list()
    .filter("published = true")
    .sort("-created_at")
    .limit(10)
    .execute()
    .await?;

// Get single record
let post: Post = client
    .collection("posts")
    .get("record_id")
    .await?;

// Update record
let updated_post: Post = client
    .collection("posts")
    .update("record_id", serde_json::json!({
        "published": true
    }))
    .await?;

// Delete record
client
    .collection("posts")
    .delete("record_id")
    .await?;
```

### Real-time Subscriptions

```rust
use ferritedb_sdk::realtime::{RealtimeEvent, RealtimeEventType};

// Subscribe to collection changes
let mut subscription = client
    .realtime()
    .subscribe("posts")
    .await?;

while let Some(event) = subscription.next().await {
    match event {
        Ok(RealtimeEvent { event_type: RealtimeEventType::RecordCreated, record, .. }) => {
            println!("New record created: {:?}", record);
        }
        Ok(RealtimeEvent { event_type: RealtimeEventType::RecordUpdated, record, .. }) => {
            println!("Record updated: {:?}", record);
        }
        Ok(RealtimeEvent { event_type: RealtimeEventType::RecordDeleted, record_id, .. }) => {
            println!("Record deleted: {}", record_id);
        }
        Err(e) => {
            eprintln!("Real-time error: {}", e);
        }
    }
}
```

## Python SDK

### Installation

```bash
pip install ferritedb-python
```

### Basic Usage

```python
import asyncio
from ferritedb import FerriteDB

async def main():
    # Initialize client
    client = FerriteDB(
        url="https://your-ferritedb-instance.com",
        timeout=30
    )
    
    # With API key
    client = FerriteDB(
        url="https://your-ferritedb-instance.com",
        api_key="your-api-key"
    )
    
    # Authentication
    auth_result = await client.auth.login(
        email="user@example.com",
        password="securepassword"
    )
    
    client.set_auth_token(auth_result.token)
    
    # Create record
    post = await client.collection("posts").create({
        "title": "My Python Post",
        "content": "Content from Python!",
        "published": False
    })
    
    # List records
    posts = await client.collection("posts").list(
        filter="published = true",
        sort="-created_at",
        limit=10
    )
    
    print(f"Found {len(posts.records)} posts")

if __name__ == "__main__":
    asyncio.run(main())
```

### Django Integration

```python
# settings.py
FERRITEDB_URL = "https://your-ferritedb-instance.com"
FERRITEDB_API_KEY = "your-api-key"

# models.py
from django.conf import settings
from ferritedb import FerriteDB

class FerriteDBService:
    def __init__(self):
        self.client = FerriteDB(
            url=settings.FERRITEDB_URL,
            api_key=settings.FERRITEDB_API_KEY
        )
    
    async def create_post(self, title, content, author_id):
        return await self.client.collection("posts").create({
            "title": title,
            "content": content,
            "author": author_id,
            "published": False
        })
    
    async def get_published_posts(self):
        result = await self.client.collection("posts").list(
            filter="published = true",
            sort="-created_at"
        )
        return result.records

# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import asyncio

ferritedb = FerriteDBService()

@csrf_exempt
async def create_post(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        post = await ferritedb.create_post(
            title=data['title'],
            content=data['content'],
            author_id=request.user.id
        )
        return JsonResponse(post)
```

## Go SDK

### Installation

```bash
go get github.com/ferritedb/ferritedb-go
```

### Basic Usage

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/ferritedb/ferritedb-go"
)

type Post struct {
    ID        string `json:"id,omitempty"`
    Title     string `json:"title"`
    Content   string `json:"content"`
    Published bool   `json:"published"`
    Author    string `json:"author"`
}

func main() {
    // Initialize client
    client := ferritedb.New(&ferritedb.Config{
        URL:     "https://your-ferritedb-instance.com",
        Timeout: 30,
    })
    
    // With API key
    client = ferritedb.New(&ferritedb.Config{
        URL:    "https://your-ferritedb-instance.com",
        APIKey: "your-api-key",
    })
    
    ctx := context.Background()
    
    // Authentication
    authResult, err := client.Auth.Login(ctx, &ferritedb.LoginRequest{
        Email:    "user@example.com",
        Password: "securepassword",
    })
    if err != nil {
        log.Fatal(err)
    }
    
    client.SetAuthToken(authResult.Token)
    
    // Create record
    post := &Post{
        Title:     "My Go Post",
        Content:   "Content from Go!",
        Published: false,
        Author:    "user_id",
    }
    
    createdPost := &Post{}
    err = client.Collection("posts").Create(ctx, post, createdPost)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Created post: %+v\n", createdPost)
    
    // List records
    var posts []Post
    result, err := client.Collection("posts").List(ctx, &ferritedb.ListOptions{
        Filter: "published = true",
        Sort:   "-created_at",
        Limit:  10,
    }, &posts)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Found %d posts\n", len(posts))
}
```

## Error Handling

### JavaScript/TypeScript

```typescript
import { FerriteDBError, ErrorCode } from '@ferritedb/sdk-js';

try {
  const record = await client.collection('posts').create(data);
} catch (error) {
  if (error instanceof FerriteDBError) {
    switch (error.code) {
      case ErrorCode.VALIDATION_ERROR:
        console.error('Validation failed:', error.details);
        break;
      case ErrorCode.UNAUTHORIZED:
        console.error('Authentication required');
        // Redirect to login
        break;
      case ErrorCode.FORBIDDEN:
        console.error('Insufficient permissions');
        break;
      case ErrorCode.NOT_FOUND:
        console.error('Resource not found');
        break;
      case ErrorCode.RATE_LIMITED:
        console.error('Rate limit exceeded, retry after:', error.retryAfter);
        break;
      default:
        console.error('Unexpected error:', error.message);
    }
  } else {
    console.error('Network or other error:', error);
  }
}
```

### Rust

```rust
use ferritedb_sdk::{Error, ErrorKind};

match client.collection("posts").create(post).await {
    Ok(created_post) => {
        println!("Post created successfully");
    }
    Err(Error::Api { code, message, details }) => {
        match code.as_str() {
            "VALIDATION_ERROR" => {
                eprintln!("Validation failed: {}", message);
                if let Some(details) = details {
                    eprintln!("Details: {:?}", details);
                }
            }
            "UNAUTHORIZED" => {
                eprintln!("Authentication required");
                // Handle auth
            }
            "FORBIDDEN" => {
                eprintln!("Insufficient permissions");
            }
            _ => {
                eprintln!("API error: {} - {}", code, message);
            }
        }
    }
    Err(Error::Network(e)) => {
        eprintln!("Network error: {}", e);
    }
    Err(Error::Serialization(e)) => {
        eprintln!("Serialization error: {}", e);
    }
}
```

## Best Practices

### Connection Management

```typescript
// Singleton pattern for client instance
class FerriteDBClient {
  private static instance: FerriteDB;
  
  public static getInstance(): FerriteDB {
    if (!FerriteDBClient.instance) {
      FerriteDBClient.instance = new FerriteDB({
        url: process.env.FERRITEDB_URL,
        timeout: 10000,
        retries: 3
      });
    }
    return FerriteDBClient.instance;
  }
}

// Use throughout your application
const client = FerriteDBClient.getInstance();
```

### Pagination

```typescript
// Efficient pagination
async function getAllRecords(collection: string) {
  const allRecords = [];
  let page = 1;
  const perPage = 100;
  
  while (true) {
    const result = await client.collection(collection).list({
      page,
      perPage
    });
    
    allRecords.push(...result.records);
    
    if (result.records.length < perPage) {
      break; // Last page
    }
    
    page++;
  }
  
  return allRecords;
}
```

### Batch Operations

```typescript
// Efficient batch processing
async function batchCreatePosts(posts: any[]) {
  const batchSize = 50;
  const results = [];
  
  for (let i = 0; i < posts.length; i += batchSize) {
    const batch = posts.slice(i, i + batchSize);
    const batchOperations = batch.map(post => ({
      action: 'create' as const,
      data: post
    }));
    
    const batchResult = await client.collection('posts').batch(batchOperations);
    results.push(...batchResult);
  }
  
  return results;
}
```

### Caching

```typescript
// Simple in-memory cache
class CachedFerriteDB {
  private cache = new Map<string, { data: any; expires: number }>();
  private client: FerriteDB;
  
  constructor(client: FerriteDB) {
    this.client = client;
  }
  
  async get(collection: string, id: string, ttl = 300000) { // 5 minutes
    const cacheKey = `${collection}:${id}`;
    const cached = this.cache.get(cacheKey);
    
    if (cached && cached.expires > Date.now()) {
      return cached.data;
    }
    
    const record = await this.client.collection(collection).get(id);
    
    this.cache.set(cacheKey, {
      data: record,
      expires: Date.now() + ttl
    });
    
    return record;
  }
  
  invalidate(collection: string, id?: string) {
    if (id) {
      this.cache.delete(`${collection}:${id}`);
    } else {
      // Clear all entries for collection
      for (const key of this.cache.keys()) {
        if (key.startsWith(`${collection}:`)) {
          this.cache.delete(key);
        }
      }
    }
  }
}
```

### Real-time Reconnection

```typescript
// Robust real-time connection with reconnection
class RealtimeManager {
  private client: FerriteDB;
  private subscriptions = new Map<string, Function>();
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  
  constructor(client: FerriteDB) {
    this.client = client;
    this.setupConnectionHandlers();
  }
  
  private setupConnectionHandlers() {
    this.client.realtime.on('disconnect', () => {
      console.log('Real-time connection lost, attempting to reconnect...');
      this.attemptReconnect();
    });
    
    this.client.realtime.on('connect', () => {
      console.log('Real-time connection established');
      this.reconnectAttempts = 0;
      this.resubscribeAll();
    });
  }
  
  private async attemptReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached');
      return;
    }
    
    this.reconnectAttempts++;
    const delay = Math.pow(2, this.reconnectAttempts) * 1000; // Exponential backoff
    
    setTimeout(() => {
      this.client.realtime.connect();
    }, delay);
  }
  
  private resubscribeAll() {
    for (const [collection, handler] of this.subscriptions) {
      this.client.realtime.subscribe(collection, handler);
    }
  }
  
  subscribe(collection: string, handler: Function) {
    this.subscriptions.set(collection, handler);
    return this.client.realtime.subscribe(collection, handler);
  }
}
```

---

*This SDK guide is maintained by the FerriteDB team and updated with each SDK release.*