use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::Response,
};
use ferritedb_core::models::UserRole;
use ferritedb_rules::{RuleEngine, CollectionRules, RuleOperation, EvaluationContext, RequestContext};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{middleware::AuthUser, routes::{AppState, CollectionServiceTrait}};

/// WebSocket connection query parameters for authentication
#[derive(Debug, Deserialize)]
pub struct RealtimeQuery {
    /// JWT token for authentication
    pub token: Option<String>,
}

/// Realtime event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EventType {
    Created,
    Updated,
    Deleted,
}

/// Realtime event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeEvent {
    pub event_type: EventType,
    pub collection: String,
    pub record_id: Uuid,
    pub data: serde_json::Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Subscription filter for events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionFilter {
    pub collection: String,
    pub filter: Option<String>, // CEL-like expression for filtering
}

/// Client subscription message
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ClientMessage {
    Subscribe {
        id: String,
        collection: String,
        filter: Option<String>,
    },
    Unsubscribe {
        id: String,
    },
    Ping,
}

/// Server message to client
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerMessage {
    Event {
        subscription_id: String,
        event: RealtimeEvent,
    },
    Subscribed {
        id: String,
        collection: String,
    },
    Unsubscribed {
        id: String,
    },
    Error {
        message: String,
        subscription_id: Option<String>,
    },
    Pong,
}

/// Individual subscription tracking
#[derive(Debug, Clone)]
pub struct Subscription {
    pub id: String,
    pub collection: String,
    pub filter: Option<String>,
    pub user_id: Uuid,
    pub user_role: UserRole,
    pub user_email: String,
}

/// Connection state for a WebSocket client
#[derive(Debug)]
pub struct Connection {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub user_role: Option<UserRole>,
    pub user_email: Option<String>,
    pub subscriptions: HashMap<String, Subscription>,
    pub sender: mpsc::UnboundedSender<ServerMessage>,
}

/// Realtime manager for handling WebSocket connections and event broadcasting
#[derive(Clone)]
pub struct RealtimeManager {
    connections: Arc<RwLock<HashMap<Uuid, Connection>>>,
    event_sender: broadcast::Sender<RealtimeEvent>,
    rule_engine: Arc<std::sync::Mutex<RuleEngine>>,
}

impl RealtimeManager {
    /// Create a new realtime manager
    pub fn new(
        rule_engine: Arc<std::sync::Mutex<RuleEngine>>,
    ) -> Self {
        let (event_sender, _) = broadcast::channel::<RealtimeEvent>(1000);
        
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            rule_engine,
        }
    }

    /// Get a receiver for events (used by connections)
    pub fn subscribe_to_events(&self) -> broadcast::Receiver<RealtimeEvent> {
        self.event_sender.subscribe()
    }

    /// Publish an event to all subscribers
    pub fn publish_event(&self, event: RealtimeEvent) {
        debug!("Publishing event: {:?}", event);
        if let Err(e) = self.event_sender.send(event) {
            warn!("Failed to publish event: {}", e);
        }
    }

    /// Add a new connection
    pub fn add_connection(&self, connection: Connection) {
        let connection_id = connection.id;
        debug!("Adding connection: {}", connection_id);
        
        let mut connections = self.connections.write().unwrap();
        connections.insert(connection_id, connection);
        
        info!("Connection {} added. Total connections: {}", connection_id, connections.len());
    }

    /// Remove a connection
    pub fn remove_connection(&self, connection_id: Uuid) {
        debug!("Removing connection: {}", connection_id);
        
        let mut connections = self.connections.write().unwrap();
        if connections.remove(&connection_id).is_some() {
            info!("Connection {} removed. Total connections: {}", connection_id, connections.len());
        }
    }

    /// Add a subscription to a connection
    pub fn add_subscription(
        &self,
        connection_id: Uuid,
        subscription: Subscription,
    ) -> Result<(), String> {
        let mut connections = self.connections.write().unwrap();
        
        if let Some(connection) = connections.get_mut(&connection_id) {
            debug!("Adding subscription {} to connection {}", subscription.id, connection_id);
            connection.subscriptions.insert(subscription.id.clone(), subscription);
            Ok(())
        } else {
            Err("Connection not found".to_string())
        }
    }

    /// Remove a subscription from a connection
    pub fn remove_subscription(&self, connection_id: Uuid, subscription_id: &str) -> Result<(), String> {
        let mut connections = self.connections.write().unwrap();
        
        if let Some(connection) = connections.get_mut(&connection_id) {
            debug!("Removing subscription {} from connection {}", subscription_id, connection_id);
            connection.subscriptions.remove(subscription_id);
            Ok(())
        } else {
            Err("Connection not found".to_string())
        }
    }

    /// Check if a user has access to a collection based on rules
    async fn check_collection_access(
        &self,
        collection_name: &str,
        user_id: Uuid,
        user_role: UserRole,
        user_email: &str,
        collection_service: &dyn crate::routes::CollectionServiceTrait,
    ) -> Result<bool, String> {
        // Get collection to check rules
        let collection = collection_service
            .get_collection(collection_name)
            .await
            .map_err(|e| format!("Failed to get collection: {}", e))?
            .ok_or_else(|| format!("Collection '{}' not found", collection_name))?;

        // Create rules for evaluation
        let rules = CollectionRules {
            list_rule: collection.list_rule.clone(),
            view_rule: collection.view_rule.clone(),
            create_rule: collection.create_rule.clone(),
            update_rule: collection.update_rule.clone(),
            delete_rule: collection.delete_rule.clone(),
        };

        // Create evaluation context
        let user = ferritedb_rules::evaluator::User {
            id: user_id,
            email: user_email.to_string(),
            role: match user_role {
                UserRole::Admin => ferritedb_rules::evaluator::UserRole::Admin,
                UserRole::User => ferritedb_rules::evaluator::UserRole::User,
                UserRole::Service => ferritedb_rules::evaluator::UserRole::Service,
            },
            verified: true, // Assume verified for authenticated users
            created_at: chrono::Utc::now(), // We don't have this info in the context
            updated_at: chrono::Utc::now(),
        };

        let context = EvaluationContext::new()
            .with_user(user)
            .with_request(RequestContext::default());

        // Check list access (for subscriptions, we use list rule)
        let mut rule_engine = self.rule_engine.lock().unwrap();
        rule_engine
            .evaluate_collection_rule(&rules, RuleOperation::List, &context)
            .map_err(|e| format!("Rule evaluation failed: {}", e))
    }

    /// Check if an event should be sent to a specific subscription
    async fn should_send_event(
        &self,
        event: &RealtimeEvent,
        subscription: &Subscription,
        collection_service: &dyn crate::routes::CollectionServiceTrait,
    ) -> bool {
        // Check if event matches subscription collection
        if event.collection != subscription.collection {
            return false;
        }

        // Check collection access
        match self.check_collection_access(
            &subscription.collection,
            subscription.user_id,
            subscription.user_role.clone(),
            &subscription.user_email,
            collection_service,
        ).await {
            Ok(has_access) => {
                if !has_access {
                    debug!("User {} denied access to collection {}", subscription.user_id, subscription.collection);
                    return false;
                }
            }
            Err(e) => {
                warn!("Failed to check collection access: {}", e);
                return false;
            }
        }

        // TODO: Apply custom filter if specified
        // For now, we'll send all events if user has collection access
        if let Some(_filter) = &subscription.filter {
            // In a full implementation, we would evaluate the filter expression
            // against the event data using the rules engine
            debug!("Custom filter evaluation not yet implemented, allowing event");
        }

        true
    }

    /// Broadcast an event to all relevant subscribers
    pub async fn broadcast_event(
        &self,
        event: RealtimeEvent,
        collection_service: &dyn crate::routes::CollectionServiceTrait,
    ) {
        debug!("Broadcasting event for collection: {}", event.collection);
        
        let connection_snapshots: Vec<(Uuid, mpsc::UnboundedSender<ServerMessage>, Vec<Subscription>)> = {
            let connections = self.connections.read().unwrap();
            connections
                .values()
                .map(|connection| {
                    (
                        connection.id,
                        connection.sender.clone(),
                        connection
                            .subscriptions
                            .values()
                            .cloned()
                            .collect::<Vec<Subscription>>(),
                    )
                })
                .collect()
        };

        let mut sent_count = 0;

        for (connection_id, sender, subscriptions) in connection_snapshots {
            for subscription in subscriptions {
                if self
                    .should_send_event(&event, &subscription, collection_service)
                    .await
                {
                    let server_message = ServerMessage::Event {
                        subscription_id: subscription.id.clone(),
                        event: event.clone(),
                    };

                    if let Err(e) = sender.send(server_message) {
                        warn!("Failed to send event to connection {}: {}", connection_id, e);
                    } else {
                        sent_count += 1;
                    }
                }
            }
        }

        debug!("Event broadcasted to {} subscriptions", sent_count);
    }

    /// Broadcast an event immediately to all connections (used by CRUD operations)
    pub fn broadcast_event_sync(&self, event: RealtimeEvent) {
        debug!("Broadcasting event synchronously for collection: {}", event.collection);
        
        let connections = self.connections.read().unwrap();
        let mut sent_count = 0;

        for connection in connections.values() {
            for subscription in connection.subscriptions.values() {
                // Simple collection matching for sync broadcast
                if event.collection == subscription.collection {
                    let server_message = ServerMessage::Event {
                        subscription_id: subscription.id.clone(),
                        event: event.clone(),
                    };

                    if let Err(e) = connection.sender.send(server_message) {
                        warn!("Failed to send event to connection {}: {}", connection.id, e);
                    } else {
                        sent_count += 1;
                    }
                }
            }
        }

        debug!("Event broadcasted synchronously to {} subscriptions", sent_count);
    }
}

/// WebSocket upgrade handler
pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<RealtimeQuery>,
    State(state): State<AppState>,
) -> Result<Response, StatusCode> {
    // Authenticate user if token is provided
    let auth_user = if let Some(token) = query.token {
        match state.auth_service.validate_token(&token) {
            Ok(claims) => Some(AuthUser::from(&claims)),
            Err(_) => return Err(StatusCode::UNAUTHORIZED),
        }
    } else {
        None
    };

    // Create realtime manager if not already in state
    let realtime_manager = RealtimeManager::new(state.rule_engine.clone());

    Ok(ws.on_upgrade(move |socket| {
        handle_websocket(socket, auth_user, realtime_manager, state)
    }))
}

/// Handle individual WebSocket connection
async fn handle_websocket(
    socket: WebSocket,
    auth_user: Option<AuthUser>,
    realtime_manager: RealtimeManager,
    state: AppState,
) {
    let connection_id = Uuid::new_v4();
    info!("New WebSocket connection: {}", connection_id);

    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();
    let (pong_tx, mut pong_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Create connection
    let connection = Connection {
        id: connection_id,
        user_id: auth_user.as_ref().map(|u| u.id),
        user_role: auth_user.as_ref().map(|u| u.role.clone()),
        user_email: auth_user.as_ref().map(|u| u.email.clone()),
        subscriptions: HashMap::new(),
        sender: tx,
    };

    // Add connection to manager
    realtime_manager.add_connection(connection);

    // Subscribe to global events
    let mut event_receiver = realtime_manager.subscribe_to_events();

    // Spawn task to handle outgoing messages
    let outgoing_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                // Handle messages from the connection's channel
                msg = rx.recv() => {
                    match msg {
                        Some(server_msg) => {
                            let json_msg = match serde_json::to_string(&server_msg) {
                                Ok(json) => json,
                                Err(e) => {
                                    error!("Failed to serialize message: {}", e);
                                    continue;
                                }
                            };

                            if sender.send(Message::Text(json_msg)).await.is_err() {
                                debug!("Client disconnected, stopping outgoing task");
                                break;
                            }
                        }
                        None => {
                            debug!("Connection channel closed, stopping outgoing task");
                            break;
                        }
                    }
                }
                // Handle pong messages
                pong_data = pong_rx.recv() => {
                    match pong_data {
                        Some(data) => {
                            if sender.send(Message::Pong(data)).await.is_err() {
                                debug!("Failed to send pong, client likely disconnected");
                                break;
                            }
                        }
                        None => {
                            debug!("Pong channel closed");
                            break;
                        }
                    }
                }
                // Handle global events (these are handled by broadcast_event_sync now)
                event = event_receiver.recv() => {
                    match event {
                        Ok(_realtime_event) => {
                            // Events are now handled directly by broadcast_event_sync
                            // This receiver is kept for future use if needed
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!("Event receiver lagged, skipped {} events", skipped);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            debug!("Event channel closed, stopping outgoing task");
                            break;
                        }
                    }
                }
            }
        }
    });

    // Handle incoming messages
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Err(e) = handle_client_message(
                    &text,
                    connection_id,
                    &auth_user,
                    &realtime_manager,
                    &state,
                ).await {
                    error!("Error handling client message: {}", e);
                    
                    let error_msg = ServerMessage::Error {
                        message: e.to_string(),
                        subscription_id: None,
                    };
                    
                    if let Some(connection) = realtime_manager
                        .connections
                        .read()
                        .unwrap()
                        .get(&connection_id)
                    {
                        if let Err(send_err) = connection.sender.send(error_msg) {
                            warn!("Failed to send error message: {}", send_err);
                        }
                    }
                }
            }
            Ok(Message::Close(_)) => {
                debug!("WebSocket connection closed by client");
                break;
            }
            Ok(Message::Ping(data)) => {
                if pong_tx.send(data).is_err() {
                    debug!("Failed to send pong data to outgoing task");
                    break;
                }
            }
            Ok(_) => {
                // Ignore other message types
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
        }
    }

    // Cleanup
    outgoing_task.abort();
    realtime_manager.remove_connection(connection_id);
    info!("WebSocket connection {} closed", connection_id);
}

/// Handle incoming client messages
async fn handle_client_message(
    text: &str,
    connection_id: Uuid,
    auth_user: &Option<AuthUser>,
    realtime_manager: &RealtimeManager,
    state: &AppState,
) -> Result<(), String> {
    let client_msg: ClientMessage = serde_json::from_str(text)
        .map_err(|e| format!("Invalid message format: {}", e))?;

    match client_msg {
        ClientMessage::Subscribe { id, collection, filter } => {
            // Require authentication for subscriptions
            let auth_user = auth_user.as_ref()
                .ok_or_else(|| "Authentication required for subscriptions".to_string())?;

            // Check if user has access to the collection
            let has_access = realtime_manager.check_collection_access(
                &collection,
                auth_user.id,
                auth_user.role.clone(),
                &auth_user.email,
                state.collection_service.as_ref(),
            ).await?;

            if !has_access {
                return Err(format!("Access denied to collection '{}'", collection));
            }

            // Create subscription
            let subscription = Subscription {
                id: id.clone(),
                collection: collection.clone(),
                filter,
                user_id: auth_user.id,
                user_role: auth_user.role.clone(),
                user_email: auth_user.email.clone(),
            };

            // Add subscription to connection
            realtime_manager.add_subscription(connection_id, subscription)?;

            // Send confirmation
            let response = ServerMessage::Subscribed {
                id,
                collection,
            };

            if let Some(connection) = realtime_manager.connections.read().unwrap().get(&connection_id) {
                connection.sender.send(response)
                    .map_err(|e| format!("Failed to send response: {}", e))?;
            }
        }
        ClientMessage::Unsubscribe { id } => {
            realtime_manager.remove_subscription(connection_id, &id)?;

            let response = ServerMessage::Unsubscribed { id };

            if let Some(connection) = realtime_manager.connections.read().unwrap().get(&connection_id) {
                connection.sender.send(response)
                    .map_err(|e| format!("Failed to send response: {}", e))?;
            }
        }
        ClientMessage::Ping => {
            let response = ServerMessage::Pong;

            if let Some(connection) = realtime_manager.connections.read().unwrap().get(&connection_id) {
                connection.sender.send(response)
                    .map_err(|e| format!("Failed to send pong: {}", e))?;
            }
        }
    }

    Ok(())
}

use futures_util::{SinkExt, StreamExt};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{collections::HashMap, sync::Arc};
    use tokio::sync::mpsc;
    use uuid::Uuid;

    // Mock auth service for testing
    struct MockAuthService;
    
    impl MockAuthService {
        fn new() -> Self {
            Self
        }
    }

    // Mock rule engine for testing
    struct MockRuleEngine;
    
    impl MockRuleEngine {
        fn new() -> Self {
            Self
        }
    }

    #[test]
    fn test_realtime_manager_creation() {
        let auth_service = Arc::new(MockAuthService::new());
        let rule_engine = Arc::new(std::sync::Mutex::new(MockRuleEngine::new()));
        
        // Create a simple manager for testing
        let (event_sender, _) = broadcast::channel::<RealtimeEvent>(1000);
        let connections: Arc<RwLock<HashMap<Uuid, Connection>>> =
            Arc::new(RwLock::new(HashMap::new()));
        
        // Test that we can create the basic structure
        assert!(connections.read().unwrap().is_empty());
    }

    #[test]
    fn test_event_creation() {
        let event = RealtimeEvent {
            event_type: EventType::Created,
            collection: "posts".to_string(),
            record_id: Uuid::new_v4(),
            data: json!({"title": "Test Post"}),
            timestamp: chrono::Utc::now(),
        };

        // Test event structure
        assert_eq!(event.event_type, EventType::Created);
        assert_eq!(event.collection, "posts");
        assert!(event.data.is_object());
    }

    #[test]
    fn test_connection_structure() {
        let connection_id = Uuid::new_v4();
        let (tx, _rx) = mpsc::unbounded_channel();

        let connection = Connection {
            id: connection_id,
            user_id: Some(Uuid::new_v4()),
            user_role: Some(ferritedb_core::models::UserRole::User),
            user_email: Some("test@example.com".to_string()),
            subscriptions: HashMap::new(),
            sender: tx,
        };

        // Test connection structure
        assert_eq!(connection.id, connection_id);
        assert!(connection.user_id.is_some());
        assert!(connection.subscriptions.is_empty());
    }

    #[test]
    fn test_subscription_structure() {
        let user_id = Uuid::new_v4();

        let subscription = Subscription {
            id: "sub1".to_string(),
            collection: "posts".to_string(),
            filter: None,
            user_id,
            user_role: ferritedb_core::models::UserRole::User,
            user_email: "test@example.com".to_string(),
        };

        // Test subscription structure
        assert_eq!(subscription.id, "sub1");
        assert_eq!(subscription.collection, "posts");
        assert!(subscription.filter.is_none());
        assert_eq!(subscription.user_id, user_id);
    }

    #[test]
    fn test_client_message_serialization() {
        let subscribe_msg = ClientMessage::Subscribe {
            id: "sub1".to_string(),
            collection: "posts".to_string(),
            filter: Some("record.published == true".to_string()),
        };

        let json = serde_json::to_string(&subscribe_msg).unwrap();
        let deserialized: ClientMessage = serde_json::from_str(&json).unwrap();

        match deserialized {
            ClientMessage::Subscribe { id, collection, filter } => {
                assert_eq!(id, "sub1");
                assert_eq!(collection, "posts");
                assert_eq!(filter, Some("record.published == true".to_string()));
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_server_message_serialization() {
        let event = RealtimeEvent {
            event_type: EventType::Created,
            collection: "posts".to_string(),
            record_id: Uuid::new_v4(),
            data: json!({"title": "Test Post"}),
            timestamp: chrono::Utc::now(),
        };

        let server_msg = ServerMessage::Event {
            subscription_id: "sub1".to_string(),
            event,
        };

        let json = serde_json::to_string(&server_msg).unwrap();
        let deserialized: ServerMessage = serde_json::from_str(&json).unwrap();

        match deserialized {
            ServerMessage::Event { subscription_id, event } => {
                assert_eq!(subscription_id, "sub1");
                assert_eq!(event.collection, "posts");
                assert_eq!(event.event_type, EventType::Created);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_event_type_serialization() {
        let created = EventType::Created;
        let updated = EventType::Updated;
        let deleted = EventType::Deleted;

        assert_eq!(serde_json::to_string(&created).unwrap(), "\"created\"");
        assert_eq!(serde_json::to_string(&updated).unwrap(), "\"updated\"");
        assert_eq!(serde_json::to_string(&deleted).unwrap(), "\"deleted\"");

        let created_deser: EventType = serde_json::from_str("\"created\"").unwrap();
        let updated_deser: EventType = serde_json::from_str("\"updated\"").unwrap();
        let deleted_deser: EventType = serde_json::from_str("\"deleted\"").unwrap();

        assert_eq!(created_deser, EventType::Created);
        assert_eq!(updated_deser, EventType::Updated);
        assert_eq!(deleted_deser, EventType::Deleted);
    }



    #[test]
    fn test_ping_pong_messages() {
        let ping_msg = ClientMessage::Ping;
        let pong_msg = ServerMessage::Pong;

        // Test serialization
        let ping_json = serde_json::to_string(&ping_msg).unwrap();
        let pong_json = serde_json::to_string(&pong_msg).unwrap();

        assert_eq!(ping_json, r#"{"type":"ping"}"#);
        assert_eq!(pong_json, r#"{"type":"pong"}"#);

        // Test deserialization
        let ping_deser: ClientMessage = serde_json::from_str(&ping_json).unwrap();
        let pong_deser: ServerMessage = serde_json::from_str(&pong_json).unwrap();

        assert!(matches!(ping_deser, ClientMessage::Ping));
        assert!(matches!(pong_deser, ServerMessage::Pong));
    }

    #[test]
    fn test_error_message() {
        let error_msg = ServerMessage::Error {
            message: "Access denied".to_string(),
            subscription_id: Some("sub1".to_string()),
        };

        let json = serde_json::to_string(&error_msg).unwrap();
        let deserialized: ServerMessage = serde_json::from_str(&json).unwrap();

        match deserialized {
            ServerMessage::Error { message, subscription_id } => {
                assert_eq!(message, "Access denied");
                assert_eq!(subscription_id, Some("sub1".to_string()));
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_subscription_confirmation_messages() {
        let subscribed_msg = ServerMessage::Subscribed {
            id: "sub1".to_string(),
            collection: "posts".to_string(),
        };

        let unsubscribed_msg = ServerMessage::Unsubscribed {
            id: "sub1".to_string(),
        };

        // Test serialization
        let sub_json = serde_json::to_string(&subscribed_msg).unwrap();
        let unsub_json = serde_json::to_string(&unsubscribed_msg).unwrap();

        // Test deserialization
        let sub_deser: ServerMessage = serde_json::from_str(&sub_json).unwrap();
        let unsub_deser: ServerMessage = serde_json::from_str(&unsub_json).unwrap();

        match sub_deser {
            ServerMessage::Subscribed { id, collection } => {
                assert_eq!(id, "sub1");
                assert_eq!(collection, "posts");
            }
            _ => panic!("Wrong message type"),
        }

        match unsub_deser {
            ServerMessage::Unsubscribed { id } => {
                assert_eq!(id, "sub1");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_user_role_types() {
        // Test that we can create different user roles
        let admin_role = ferritedb_core::models::UserRole::Admin;
        let user_role = ferritedb_core::models::UserRole::User;
        let service_role = ferritedb_core::models::UserRole::Service;

        // Test role comparison
        assert_ne!(admin_role, user_role);
        assert_ne!(user_role, service_role);
        assert_ne!(admin_role, service_role);
    }
}
