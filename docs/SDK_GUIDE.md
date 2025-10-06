# FerriteDB SDK Guide

This guide covers all available SDKs for FerriteDB, including installation, configuration, and usage examples for different programming languages and frameworks.

## Table of Contents

- [Overview](#overview)
- [Rust SDK](#rust-sdk)
- [JavaScript/TypeScript SDK](#javascripttypescript-sdk)
- [Python SDK](#python-sdk)
- [Go SDK](#go-sdk)
- [Authentication](#authentication)
- [Collections Management](#collections-management)
- [Records Operations](#records-operations)
- [File Management](#file-management)
- [Real-time Features](#real-time-features)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)
- [Examples and Tutorials](#examples-and-tutorials)

## Overview

FerriteDB provides official SDKs for multiple programming languages, making it easy to integrate with your applications. All SDKs provide:

- **Type Safety**: Strong typing for better development experience
- **Async Support**: Non-blocking operations for better performance
- **Authentication**: Built-in JWT token management
- **Real-time**: WebSocket support for live updates
- **Error Handling**: Comprehensive error types and handling
- **Validation**: Client-side validation before API calls

## Rust SDK

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
ferritedb-sdk = "0.1.0"
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
```

### Basic Setup

```rust
use ferritedb_sdk::{FerriteDB, Config, AuthCredentials};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Post {
    title: String,
    content: String,
    published: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize client
    let config = Config::new("https://api.yourdomain.com")
        .with_timeout(30);
    
    let client = FerriteDB::new(config);

    // Authenticate
    let auth = client.auth()
        .login("user@example.com", "password")
        .await?;

    println!("Authenticated as: {}", auth.user.email);

    // Create a record
    let post = Post {
        title: "My First Post".to_string(),
        content: "This is the content of my first post.".to_string(),
        published: true,
    };

    let created_post = client.collection("posts")
        .create(&post)
        .await?;

    println!("Created post: {:?}", created_post);

    Ok(())
}
```

### Advanced Usage

```rust
use ferritedb_sdk::{
    FerriteDB, Config, 
    collections::{CreateRecordRequest, ListOptions, FilterOperator},
    realtime::{RealtimeEvent, SubscriptionOptions},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = FerriteDB::new(Config::new("https://api.yourdomain.com"));

    // Authenticate with API key
    client.auth().with_api_key("your-api-key").await?;

    // List records with filtering and pagination
    let posts = client.collection("posts")
        .list(ListOptions {
            page: Some(1),
            per_page: Some(10),
            sort: Some("-created_at".to_string()),
            filter: Some("published=true".to_string()),
            fields: Some(vec!["id".to_string(), "title".to_string()]),
        })
        .await?;

    println!("Found {} posts", posts.records.len());

    // Update a record
    let updated_post = client.collection("posts")
        .update("post_id", &json!({
            "title": "Updated Title"
        }))
        .await?;

    // Real-time subscription
    let mut subscription = client.realtime()
        .subscribe("posts", SubscriptionOptions {
            filter: Some("published=true".to_string()),
        })
        .await?;

    // Listen for events
    while let Some(event) = subscription.next().await {
        match event? {
            RealtimeEvent::RecordCreated { collection, record } => {
                println!("New post created: {:?}", record);
            }
            RealtimeEvent::RecordUpdated { collection, record } => {
                println!("Post updated: {:?}", record);
            }
            RealtimeEvent::RecordDeleted { collection, record_id } => {
                println!("Post deleted: {}", record_id);
            }
        }
    }

    Ok(())
}
```

### File Upload

```rust
use ferritedb_sdk::files::{FileUpload, UploadOptions};
use tokio::fs;

async fn upload_file() -> Result<(), Box<dyn std::error::Error>> {
    let client = FerriteDB::new(Config::new("https://api.yourdomain.com"));
    client.auth().login("user@example.com", "password").await?;

    // Upload from file path
    let file_data = fs::read("image.jpg").await?;
    let uploaded_file = client.files()
        .upload(FileUpload {
            filename: "image.jpg".to_string(),
            data: file_data,
            content_type: Some("image/jpeg".to_string()),
        }, UploadOptions {
            collection: Some("posts".to_string()),
            record_id: Some("post_123".to_string()),
            field: Some("featured_image".to_string()),
        })
        .await?;

    println!("File uploaded: {}", uploaded_file.url);
    Ok(())
}
```

## JavaScript/TypeScript SDK

### Installation

```bash
npm install @ferritedb/sdk
# or
yarn add @ferritedb/sdk
```

### Basic Setup

```typescript
import { FerriteDB } from '@ferritedb/sdk';

interface Post {
  id?: string;
  title: string;
  content: string;
  published: boolean;
  created_at?: string;
  updated_at?: string;
}

const client = new FerriteDB({
  url: 'https://api.yourdomain.com',
  timeout: 30000,
});

async function main() {
  try {
    // Authenticate
    const auth = await client.auth.login('user@example.com', 'password');
    console.log('Authenticated as:', auth.user.email);

    // Create a record
    const post: Post = {
      title: 'My First Post',
      content: 'This is the content of my first post.',
      published: true,
    };

    const createdPost = await client.collection('posts').create<Post>(post);
    console.log('Created post:', createdPost);

    // List records
    const posts = await client.collection('posts').list<Post>({
      page: 1,
      perPage: 10,
      sort: '-created_at',
      filter: 'published=true',
    });

    console.log('Posts:', posts.records);
  } catch (error) {
    console.error('Error:', error);
  }
}

main();
```

### React Integration

```tsx
import React, { useState, useEffect } from 'react';
import { FerriteDB } from '@ferritedb/sdk';

const client = new FerriteDB({ url: 'https://api.yourdomain.com' });

interface Post {
  id: string;
  title: string;
  content: string;
  published: boolean;
}

export const PostsList: React.FC = () => {
  const [posts, setPosts] = useState<Post[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchPosts = async () => {
      try {
        await client.auth.login('user@example.com', 'password');
        const response = await client.collection('posts').list<Post>();
        setPosts(response.records);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'An error occurred');
      } finally {
        setLoading(false);
      }
    };

    fetchPosts();

    // Real-time subscription
    const subscription = client.realtime.subscribe('posts', (event) => {
      switch (event.type) {
        case 'record_created':
          setPosts(prev => [event.record as Post, ...prev]);
          break;
        case 'record_updated':
          setPosts(prev => prev.map(post => 
            post.id === event.record.id ? event.record as Post : post
          ));
          break;
        case 'record_deleted':
          setPosts(prev => prev.filter(post => post.id !== event.record_id));
          break;
      }
    });

    return () => {
      subscription.unsubscribe();
    };
  }, []);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;

  return (
    <div>
      <h1>Posts</h1>
      {posts.map(post => (
        <div key={post.id}>
          <h2>{post.title}</h2>
          <p>{post.content}</p>
        </div>
      ))}
    </div>
  );
};
```

### Node.js Server Integration

```typescript
import express from 'express';
import { FerriteDB } from '@ferritedb/sdk';

const app = express();
const client = new FerriteDB({ url: 'https://api.yourdomain.com' });

app.use(express.json());

// Middleware for authentication
app.use(async (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token) {
    try {
      await client.auth.validateToken(token);
      next();
    } catch (error) {
      res.status(401).json({ error: 'Invalid token' });
    }
  } else {
    res.status(401).json({ error: 'No token provided' });
  }
});

// Proxy API endpoints
app.get('/api/posts', async (req, res) => {
  try {
    const posts = await client.collection('posts').list({
      page: parseInt(req.query.page as string) || 1,
      perPage: parseInt(req.query.per_page as string) || 10,
      filter: req.query.filter as string,
    });
    res.json(posts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/posts', async (req, res) => {
  try {
    const post = await client.collection('posts').create(req.body);
    res.status(201).json(post);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

## Python SDK

### Installation

```bash
pip install ferritedb-sdk
```

### Basic Setup

```python
import asyncio
from ferritedb_sdk import FerriteDB, Config
from typing import Dict, Any

async def main():
    # Initialize client
    config = Config(
        url="https://api.yourdomain.com",
        timeout=30
    )
    client = FerriteDB(config)

    # Authenticate
    auth = await client.auth.login("user@example.com", "password")
    print(f"Authenticated as: {auth.user.email}")

    # Create a record
    post_data = {
        "title": "My First Post",
        "content": "This is the content of my first post.",
        "published": True
    }

    created_post = await client.collection("posts").create(post_data)
    print(f"Created post: {created_post}")

    # List records
    posts = await client.collection("posts").list(
        page=1,
        per_page=10,
        sort="-created_at",
        filter="published=true"
    )

    print(f"Found {len(posts.records)} posts")

if __name__ == "__main__":
    asyncio.run(main())
```

### Django Integration

```python
# models.py
from django.db import models
from ferritedb_sdk import FerriteDB
from django.conf import settings

class PostManager(models.Manager):
    def __init__(self):
        super().__init__()
        self.client = FerriteDB(settings.FERRITEDB_CONFIG)

    async def sync_from_ferritedb(self):
        """Sync posts from FerriteDB to local database"""
        await self.client.auth.login(
            settings.FERRITEDB_EMAIL,
            settings.FERRITEDB_PASSWORD
        )
        
        posts = await self.client.collection("posts").list()
        
        for post_data in posts.records:
            post, created = await self.aupdate_or_create(
                ferritedb_id=post_data["id"],
                defaults={
                    "title": post_data["title"],
                    "content": post_data["content"],
                    "published": post_data["published"],
                }
            )

class Post(models.Model):
    ferritedb_id = models.CharField(max_length=255, unique=True)
    title = models.CharField(max_length=200)
    content = models.TextField()
    published = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = PostManager()

# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json

@csrf_exempt
@require_http_methods(["POST"])
async def create_post(request):
    try:
        data = json.loads(request.body)
        
        # Create in FerriteDB
        client = FerriteDB(settings.FERRITEDB_CONFIG)
        await client.auth.login(
            settings.FERRITEDB_EMAIL,
            settings.FERRITEDB_PASSWORD
        )
        
        post = await client.collection("posts").create(data)
        
        return JsonResponse(post, status=201)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)
```

### FastAPI Integration

```python
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from ferritedb_sdk import FerriteDB
from typing import List, Optional

app = FastAPI()
client = FerriteDB({"url": "https://api.yourdomain.com"})

class PostCreate(BaseModel):
    title: str
    content: str
    published: bool = False

class Post(BaseModel):
    id: str
    title: str
    content: str
    published: bool
    created_at: str
    updated_at: str

async def get_authenticated_client():
    await client.auth.login("user@example.com", "password")
    return client

@app.post("/posts/", response_model=Post)
async def create_post(
    post: PostCreate,
    client: FerriteDB = Depends(get_authenticated_client)
):
    try:
        created_post = await client.collection("posts").create(post.dict())
        return Post(**created_post)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/posts/", response_model=List[Post])
async def list_posts(
    page: int = 1,
    per_page: int = 10,
    client: FerriteDB = Depends(get_authenticated_client)
):
    try:
        posts = await client.collection("posts").list(
            page=page,
            per_page=per_page
        )
        return [Post(**post) for post in posts.records]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Real-time WebSocket endpoint
@app.websocket("/ws/posts")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    
    async def handle_event(event):
        await websocket.send_json(event)
    
    subscription = await client.realtime.subscribe("posts", handle_event)
    
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await subscription.unsubscribe()
```

## Go SDK

### Installation

```bash
go get github.com/foozio/ferritedb-go-sdk
```

### Basic Setup

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/foozio/ferritedb-go-sdk"
)

type Post struct {
    ID        string `json:"id,omitempty"`
    Title     string `json:"title"`
    Content   string `json:"content"`
    Published bool   `json:"published"`
    CreatedAt string `json:"created_at,omitempty"`
    UpdatedAt string `json:"updated_at,omitempty"`
}

func main() {
    // Initialize client
    client := ferritedb.NewClient(&ferritedb.Config{
        URL:     "https://api.yourdomain.com",
        Timeout: 30,
    })

    ctx := context.Background()

    // Authenticate
    auth, err := client.Auth.Login(ctx, "user@example.com", "password")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Authenticated as: %s\n", auth.User.Email)

    // Create a record
    post := Post{
        Title:     "My First Post",
        Content:   "This is the content of my first post.",
        Published: true,
    }

    var createdPost Post
    err = client.Collection("posts").Create(ctx, post, &createdPost)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Created post: %+v\n", createdPost)

    // List records
    var posts struct {
        Records []Post `json:"records"`
    }
    
    err = client.Collection("posts").List(ctx, &ferritedb.ListOptions{
        Page:    1,
        PerPage: 10,
        Sort:    "-created_at",
        Filter:  "published=true",
    }, &posts)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Found %d posts\n", len(posts.Records))
}
```

### Gin Web Framework Integration

```go
package main

import (
    "net/http"
    "strconv"
    
    "github.com/gin-gonic/gin"
    "github.com/foozio/ferritedb-go-sdk"
)

var client *ferritedb.Client

func init() {
    client = ferritedb.NewClient(&ferritedb.Config{
        URL: "https://api.yourdomain.com",
    })
}

func authMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        token := c.GetHeader("Authorization")
        if token == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
            c.Abort()
            return
        }

        // Remove "Bearer " prefix
        if len(token) > 7 && token[:7] == "Bearer " {
            token = token[7:]
        }

        err := client.Auth.ValidateToken(c.Request.Context(), token)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        c.Next()
    }
}

func listPosts(c *gin.Context) {
    page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
    perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "10"))
    filter := c.Query("filter")

    var posts struct {
        Records []Post `json:"records"`
    }

    err := client.Collection("posts").List(c.Request.Context(), &ferritedb.ListOptions{
        Page:    page,
        PerPage: perPage,
        Filter:  filter,
    }, &posts)

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, posts)
}

func createPost(c *gin.Context) {
    var post Post
    if err := c.ShouldBindJSON(&post); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    var createdPost Post
    err := client.Collection("posts").Create(c.Request.Context(), post, &createdPost)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusCreated, createdPost)
}

func main() {
    r := gin.Default()
    
    // Public routes
    r.POST("/auth/login", func(c *gin.Context) {
        var credentials struct {
            Email    string `json:"email"`
            Password string `json:"password"`
        }
        
        if err := c.ShouldBindJSON(&credentials); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }
        
        auth, err := client.Auth.Login(c.Request.Context(), credentials.Email, credentials.Password)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
            return
        }
        
        c.JSON(http.StatusOK, auth)
    })

    // Protected routes
    api := r.Group("/api")
    api.Use(authMiddleware())
    {
        api.GET("/posts", listPosts)
        api.POST("/posts", createPost)
    }

    r.Run(":8080")
}
```

## Authentication

### JWT Token Management

All SDKs handle JWT token management automatically:

```typescript
// JavaScript/TypeScript
const client = new FerriteDB({ url: 'https://api.yourdomain.com' });

// Login (tokens are stored automatically)
await client.auth.login('user@example.com', 'password');

// Tokens are automatically included in subsequent requests
const posts = await client.collection('posts').list();

// Refresh token automatically when needed
// (handled internally by the SDK)

// Manual token refresh
await client.auth.refresh();

// Logout (clears stored tokens)
await client.auth.logout();
```

```rust
// Rust
let client = FerriteDB::new(Config::new("https://api.yourdomain.com"));

// Login with automatic token management
let auth = client.auth().login("user@example.com", "password").await?;

// Use API key instead of login
client.auth().with_api_key("your-api-key").await?;

// Manual token validation
let is_valid = client.auth().validate_current_token().await?;
```

### API Key Authentication

```python
# Python
client = FerriteDB({"url": "https://api.yourdomain.com"})

# Use API key for service-to-service communication
await client.auth.with_api_key("your-api-key")

# Or set in config
config = Config(
    url="https://api.yourdomain.com",
    api_key="your-api-key"
)
client = FerriteDB(config)
```

## Collections Management

### Creating Collections

```typescript
// TypeScript
const collectionSchema = {
  name: 'posts',
  type: 'base',
  schema: {
    fields: [
      {
        name: 'title',
        type: 'text',
        required: true,
        options: { max_length: 200 }
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
      },
      {
        name: 'author',
        type: 'relation',
        required: true,
        options: {
          target_collection: 'users',
          cascade_delete: false
        }
      }
    ]
  },
  rules: {
    list: "user.role == 'admin' || record.published == true",
    view: "user.role == 'admin' || record.published == true",
    create: "user.role == 'admin' || user.role == 'user'",
    update: "user.role == 'admin' || record.author == user.id",
    delete: "user.role == 'admin' || record.author == user.id"
  }
};

const collection = await client.collections.create(collectionSchema);
```

### Updating Collection Schema

```rust
// Rust
use ferritedb_sdk::collections::{UpdateCollectionRequest, FieldDefinition, FieldType};

let update_request = UpdateCollectionRequest {
    schema: Some(CollectionSchema {
        fields: vec![
            FieldDefinition {
                name: "tags".to_string(),
                field_type: FieldType::Text,
                required: false,
                options: Some(json!({ "is_array": true })),
            }
        ],
    }),
    rules: None,
};

let updated_collection = client.collections()
    .update("posts", update_request)
    .await?;
```

## Records Operations

### CRUD Operations

```python
# Python - Complete CRUD example
import asyncio
from ferritedb_sdk import FerriteDB

async def crud_example():
    client = FerriteDB({"url": "https://api.yourdomain.com"})
    await client.auth.login("user@example.com", "password")

    # Create
    post_data = {
        "title": "My New Post",
        "content": "This is the content.",
        "published": False
    }
    created_post = await client.collection("posts").create(post_data)
    post_id = created_post["id"]

    # Read (single record)
    post = await client.collection("posts").get(post_id)
    print(f"Retrieved post: {post['title']}")

    # Update
    updated_post = await client.collection("posts").update(post_id, {
        "title": "Updated Title",
        "published": True
    })

    # List with filtering
    published_posts = await client.collection("posts").list(
        filter="published=true",
        sort="-created_at",
        page=1,
        per_page=10
    )

    # Delete
    await client.collection("posts").delete(post_id)
    print("Post deleted")

asyncio.run(crud_example())
```

### Batch Operations

```go
// Go - Batch operations
func batchOperations(client *ferritedb.Client) error {
    ctx := context.Background()

    // Batch create
    posts := []Post{
        {Title: "Post 1", Content: "Content 1", Published: true},
        {Title: "Post 2", Content: "Content 2", Published: false},
        {Title: "Post 3", Content: "Content 3", Published: true},
    }

    var createdPosts []Post
    err := client.Collection("posts").CreateBatch(ctx, posts, &createdPosts)
    if err != nil {
        return err
    }

    // Batch update
    updates := []ferritedb.BatchUpdate{
        {ID: createdPosts[0].ID, Data: map[string]interface{}{"published": false}},
        {ID: createdPosts[1].ID, Data: map[string]interface{}{"published": true}},
    }

    err = client.Collection("posts").UpdateBatch(ctx, updates)
    if err != nil {
        return err
    }

    // Batch delete
    ids := []string{createdPosts[0].ID, createdPosts[1].ID}
    err = client.Collection("posts").DeleteBatch(ctx, ids)
    if err != nil {
        return err
    }

    return nil
}
```

## File Management

### File Upload and Management

```typescript
// TypeScript - File upload with progress
import { FerriteDB } from '@ferritedb/sdk';

async function uploadWithProgress(file: File) {
  const client = new FerriteDB({ url: 'https://api.yourdomain.com' });
  await client.auth.login('user@example.com', 'password');

  const uploadedFile = await client.files.upload(file, {
    collection: 'posts',
    recordId: 'post_123',
    field: 'featured_image',
    onProgress: (progress) => {
      console.log(`Upload progress: ${progress.percentage}%`);
    }
  });

  console.log('File uploaded:', uploadedFile.url);
  return uploadedFile;
}

// File management
async function manageFiles() {
  const client = new FerriteDB({ url: 'https://api.yourdomain.com' });
  await client.auth.login('user@example.com', 'password');

  // List files
  const files = await client.files.list({
    collection: 'posts',
    mimeType: 'image/*'
  });

  // Get file metadata
  const fileInfo = await client.files.get('file_id');

  // Download file
  const fileBlob = await client.files.download('file_id');

  // Delete file
  await client.files.delete('file_id');
}
```

## Real-time Features

### WebSocket Subscriptions

```rust
// Rust - Real-time subscriptions
use ferritedb_sdk::realtime::{RealtimeEvent, SubscriptionOptions};
use futures_util::StreamExt;

async fn realtime_example() -> Result<(), Box<dyn std::error::Error>> {
    let client = FerriteDB::new(Config::new("https://api.yourdomain.com"));
    client.auth().login("user@example.com", "password").await?;

    // Subscribe to collection changes
    let mut subscription = client.realtime()
        .subscribe("posts", SubscriptionOptions {
            filter: Some("published=true".to_string()),
        })
        .await?;

    // Handle events
    while let Some(event) = subscription.next().await {
        match event? {
            RealtimeEvent::RecordCreated { collection, record } => {
                println!("New post created in {}: {:?}", collection, record);
            }
            RealtimeEvent::RecordUpdated { collection, record } => {
                println!("Post updated in {}: {:?}", collection, record);
            }
            RealtimeEvent::RecordDeleted { collection, record_id } => {
                println!("Post deleted from {}: {}", collection, record_id);
            }
        }
    }

    Ok(())
}
```

```javascript
// JavaScript - Real-time with reconnection
class RealtimeManager {
  constructor(client) {
    this.client = client;
    this.subscriptions = new Map();
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
  }

  async subscribe(collection, callback, options = {}) {
    try {
      const subscription = await this.client.realtime.subscribe(
        collection,
        (event) => {
          this.reconnectAttempts = 0; // Reset on successful event
          callback(event);
        },
        {
          ...options,
          onDisconnect: () => this.handleDisconnect(collection, callback, options),
          onError: (error) => this.handleError(error, collection, callback, options)
        }
      );

      this.subscriptions.set(collection, subscription);
      return subscription;
    } catch (error) {
      console.error('Failed to subscribe:', error);
      throw error;
    }
  }

  async handleDisconnect(collection, callback, options) {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = Math.pow(2, this.reconnectAttempts) * 1000; // Exponential backoff
      
      console.log(`Reconnecting to ${collection} in ${delay}ms (attempt ${this.reconnectAttempts})`);
      
      setTimeout(() => {
        this.subscribe(collection, callback, options);
      }, delay);
    } else {
      console.error(`Max reconnection attempts reached for ${collection}`);
    }
  }

  handleError(error, collection, callback, options) {
    console.error(`Real-time error for ${collection}:`, error);
    // Implement custom error handling logic
  }

  unsubscribe(collection) {
    const subscription = this.subscriptions.get(collection);
    if (subscription) {
      subscription.unsubscribe();
      this.subscriptions.delete(collection);
    }
  }

  unsubscribeAll() {
    for (const [collection, subscription] of this.subscriptions) {
      subscription.unsubscribe();
    }
    this.subscriptions.clear();
  }
}

// Usage
const client = new FerriteDB({ url: 'https://api.yourdomain.com' });
const realtimeManager = new RealtimeManager(client);

await client.auth.login('user@example.com', 'password');

await realtimeManager.subscribe('posts', (event) => {
  console.log('Post event:', event);
}, {
  filter: 'published=true'
});
```

## Error Handling

### Comprehensive Error Handling

```python
# Python - Error handling patterns
from ferritedb_sdk import FerriteDB, FerriteDBError, AuthenticationError, ValidationError, NotFoundError

async def robust_operation():
    client = FerriteDB({"url": "https://api.yourdomain.com"})
    
    try:
        # Authentication
        await client.auth.login("user@example.com", "password")
        
        # Create record with validation
        post_data = {
            "title": "My Post",
            "content": "Content here",
            "published": True
        }
        
        post = await client.collection("posts").create(post_data)
        return post
        
    except AuthenticationError as e:
        print(f"Authentication failed: {e}")
        # Handle authentication failure (redirect to login, etc.)
        
    except ValidationError as e:
        print(f"Validation error: {e}")
        # Handle validation errors (show form errors, etc.)
        
    except NotFoundError as e:
        print(f"Resource not found: {e}")
        # Handle missing resources
        
    except FerriteDBError as e:
        print(f"FerriteDB error: {e}")
        # Handle other FerriteDB-specific errors
        
    except Exception as e:
        print(f"Unexpected error: {e}")
        # Handle unexpected errors
        
    return None
```

```typescript
// TypeScript - Error handling with types
import { 
  FerriteDB, 
  FerriteDBError, 
  AuthenticationError, 
  ValidationError, 
  NotFoundError 
} from '@ferritedb/sdk';

class ApiService {
  private client: FerriteDB;

  constructor() {
    this.client = new FerriteDB({ url: 'https://api.yourdomain.com' });
  }

  async createPost(postData: any): Promise<Post | null> {
    try {
      const post = await this.client.collection('posts').create<Post>(postData);
      return post;
    } catch (error) {
      return this.handleError(error);
    }
  }

  private handleError(error: unknown): null {
    if (error instanceof AuthenticationError) {
      // Redirect to login
      window.location.href = '/login';
    } else if (error instanceof ValidationError) {
      // Show validation errors
      this.showValidationErrors(error.details);
    } else if (error instanceof NotFoundError) {
      // Show not found message
      this.showNotFoundMessage();
    } else if (error instanceof FerriteDBError) {
      // Show generic API error
      this.showApiError(error.message);
    } else {
      // Show unexpected error
      this.showUnexpectedError();
    }
    
    return null;
  }

  private showValidationErrors(details: any) {
    // Implementation for showing validation errors
  }

  private showNotFoundMessage() {
    // Implementation for showing not found message
  }

  private showApiError(message: string) {
    // Implementation for showing API error
  }

  private showUnexpectedError() {
    // Implementation for showing unexpected error
  }
}
```

## Best Practices

### Performance Optimization

```rust
// Rust - Performance best practices
use ferritedb_sdk::{FerriteDB, Config};
use std::time::Duration;

async fn optimized_client_setup() -> FerriteDB {
    let config = Config::new("https://api.yourdomain.com")
        .with_timeout(Duration::from_secs(30))
        .with_connection_pool_size(10)
        .with_retry_attempts(3)
        .with_cache_enabled(true)
        .with_compression(true);

    let client = FerriteDB::new(config);
    
    // Authenticate once and reuse
    client.auth().login("user@example.com", "password").await.unwrap();
    
    client
}

// Batch operations for better performance
async fn efficient_bulk_operations(client: &FerriteDB) -> Result<(), Box<dyn std::error::Error>> {
    // Instead of multiple individual creates
    let posts = vec![
        json!({"title": "Post 1", "content": "Content 1"}),
        json!({"title": "Post 2", "content": "Content 2"}),
        json!({"title": "Post 3", "content": "Content 3"}),
    ];
    
    // Use batch create
    let created_posts = client.collection("posts")
        .create_batch(posts)
        .await?;
    
    // Use field selection to reduce payload
    let posts = client.collection("posts")
        .list_with_options(ListOptions {
            fields: Some(vec!["id".to_string(), "title".to_string()]),
            per_page: Some(50),
            ..Default::default()
        })
        .await?;
    
    Ok(())
}
```

### Security Best Practices

```typescript
// TypeScript - Security best practices
class SecureApiClient {
  private client: FerriteDB;
  private tokenRefreshTimer?: NodeJS.Timeout;

  constructor() {
    this.client = new FerriteDB({
      url: 'https://api.yourdomain.com',
      // Use environment variables for sensitive data
      apiKey: process.env.FERRITEDB_API_KEY,
      timeout: 30000,
      // Enable request/response validation
      validateRequests: true,
      validateResponses: true,
    });

    this.setupTokenRefresh();
  }

  private setupTokenRefresh() {
    // Automatically refresh tokens before expiration
    this.tokenRefreshTimer = setInterval(async () => {
      try {
        await this.client.auth.refresh();
      } catch (error) {
        console.error('Token refresh failed:', error);
        // Handle refresh failure (redirect to login, etc.)
      }
    }, 50 * 60 * 1000); // Refresh every 50 minutes
  }

  async secureRequest<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (error instanceof AuthenticationError) {
        // Clear potentially compromised tokens
        await this.client.auth.logout();
        throw error;
      }
      throw error;
    }
  }

  // Input sanitization
  private sanitizeInput(data: any): any {
    // Implement input sanitization logic
    // Remove potentially dangerous content
    return data;
  }

  async createRecord(collection: string, data: any) {
    const sanitizedData = this.sanitizeInput(data);
    return this.secureRequest(() => 
      this.client.collection(collection).create(sanitizedData)
    );
  }

  destroy() {
    if (this.tokenRefreshTimer) {
      clearInterval(this.tokenRefreshTimer);
    }
  }
}
```

### Caching Strategies

```python
# Python - Caching implementation
import asyncio
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from ferritedb_sdk import FerriteDB

class CachedFerriteDBClient:
    def __init__(self, config: Dict[str, Any]):
        self.client = FerriteDB(config)
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = timedelta(minutes=5)

    def _get_cache_key(self, collection: str, operation: str, **kwargs) -> str:
        """Generate cache key for operation"""
        key_parts = [collection, operation]
        for k, v in sorted(kwargs.items()):
            key_parts.append(f"{k}:{v}")
        return ":".join(key_parts)

    def _is_cache_valid(self, cache_entry: Dict[str, Any]) -> bool:
        """Check if cache entry is still valid"""
        return datetime.now() < cache_entry["expires_at"]

    async def get_record(self, collection: str, record_id: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        cache_key = self._get_cache_key(collection, "get", id=record_id)
        
        # Check cache first
        if use_cache and cache_key in self.cache:
            cache_entry = self.cache[cache_key]
            if self._is_cache_valid(cache_entry):
                return cache_entry["data"]

        # Fetch from API
        try:
            record = await self.client.collection(collection).get(record_id)
            
            # Cache the result
            if use_cache:
                self.cache[cache_key] = {
                    "data": record,
                    "expires_at": datetime.now() + self.cache_ttl
                }
            
            return record
        except Exception as e:
            # Return cached data if available, even if expired
            if cache_key in self.cache:
                return self.cache[cache_key]["data"]
            raise e

    async def list_records(self, collection: str, **options) -> Dict[str, Any]:
        cache_key = self._get_cache_key(collection, "list", **options)
        
        # Check cache
        if cache_key in self.cache:
            cache_entry = self.cache[cache_key]
            if self._is_cache_valid(cache_entry):
                return cache_entry["data"]

        # Fetch from API
        records = await self.client.collection(collection).list(**options)
        
        # Cache the result
        self.cache[cache_key] = {
            "data": records,
            "expires_at": datetime.now() + self.cache_ttl
        }
        
        return records

    def invalidate_cache(self, collection: str = None):
        """Invalidate cache entries"""
        if collection:
            # Remove entries for specific collection
            keys_to_remove = [k for k in self.cache.keys() if k.startswith(f"{collection}:")]
            for key in keys_to_remove:
                del self.cache[key]
        else:
            # Clear entire cache
            self.cache.clear()

    async def create_record(self, collection: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create record and invalidate relevant cache"""
        record = await self.client.collection(collection).create(data)
        
        # Invalidate list caches for this collection
        self.invalidate_cache(collection)
        
        return record
```

## Examples and Tutorials

### Building a Blog Application

```typescript
// Complete blog application example
import { FerriteDB } from '@ferritedb/sdk';

interface User {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'author' | 'reader';
}

interface Post {
  id: string;
  title: string;
  content: string;
  excerpt: string;
  published: boolean;
  author_id: string;
  author?: User;
  tags: string[];
  featured_image?: string;
  created_at: string;
  updated_at: string;
}

class BlogService {
  private client: FerriteDB;

  constructor() {
    this.client = new FerriteDB({ 
      url: process.env.FERRITEDB_URL || 'https://api.yourdomain.com' 
    });
  }

  async authenticate(email: string, password: string): Promise<User> {
    const auth = await this.client.auth.login(email, password);
    return auth.user;
  }

  async createPost(postData: Omit<Post, 'id' | 'created_at' | 'updated_at'>): Promise<Post> {
    return await this.client.collection('posts').create<Post>(postData);
  }

  async getPublishedPosts(page: number = 1, perPage: number = 10): Promise<{ posts: Post[], total: number }> {
    const result = await this.client.collection('posts').list<Post>({
      filter: 'published=true',
      sort: '-created_at',
      page,
      perPage,
      expand: 'author'
    });

    return {
      posts: result.records,
      total: result.pagination.total_records
    };
  }

  async getPostBySlug(slug: string): Promise<Post | null> {
    const result = await this.client.collection('posts').list<Post>({
      filter: `slug="${slug}" && published=true`,
      expand: 'author'
    });

    return result.records[0] || null;
  }

  async updatePost(id: string, updates: Partial<Post>): Promise<Post> {
    return await this.client.collection('posts').update<Post>(id, updates);
  }

  async deletePost(id: string): Promise<void> {
    await this.client.collection('posts').delete(id);
  }

  async uploadFeaturedImage(file: File, postId: string): Promise<string> {
    const uploadedFile = await this.client.files.upload(file, {
      collection: 'posts',
      recordId: postId,
      field: 'featured_image'
    });

    return uploadedFile.url;
  }

  // Real-time subscription for live updates
  subscribeToPostUpdates(callback: (post: Post) => void): () => void {
    const subscription = this.client.realtime.subscribe('posts', (event) => {
      if (event.type === 'record_updated' && event.record.published) {
        callback(event.record as Post);
      }
    });

    return () => subscription.unsubscribe();
  }
}

// Usage in a React component
import React, { useState, useEffect } from 'react';

const BlogApp: React.FC = () => {
  const [blogService] = useState(() => new BlogService());
  const [posts, setPosts] = useState<Post[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadPosts = async () => {
      try {
        const { posts } = await blogService.getPublishedPosts();
        setPosts(posts);
      } catch (error) {
        console.error('Failed to load posts:', error);
      } finally {
        setLoading(false);
      }
    };

    loadPosts();

    // Subscribe to real-time updates
    const unsubscribe = blogService.subscribeToPostUpdates((updatedPost) => {
      setPosts(prev => prev.map(post => 
        post.id === updatedPost.id ? updatedPost : post
      ));
    });

    return unsubscribe;
  }, [blogService]);

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      <h1>Blog Posts</h1>
      {posts.map(post => (
        <article key={post.id}>
          <h2>{post.title}</h2>
          <p>{post.excerpt}</p>
          <small>By {post.author?.name} on {new Date(post.created_at).toLocaleDateString()}</small>
        </article>
      ))}
    </div>
  );
};
```

---

*This SDK guide is continuously updated with new features and improvements. For the latest documentation and examples, visit our [GitHub repository](https://github.com/foozio/ferritedb) and [documentation site](https://docs.ferritedb.com).*