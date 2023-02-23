use async_std::sync::{Arc, Mutex};
use async_trait::async_trait;
use log::debug;
use serde_json::{json, Value};

use darkfi::{
    event_graph::{
        get_current_time,
        model::{Event, EventId, ModelPtr},
        protocol_event::{SeenPtr, UnreadEvents},
    },
    net,
    rpc::{
        jsonrpc::{ErrorCode, JsonError, JsonRequest, JsonResponse, JsonResult},
        server::RequestHandler,
    },
};

use crate::genevent::GenEvent;

pub struct JsonRpcInterface {
    _nickname: String,
    unread_events: Arc<Mutex<UnreadEvents<GenEvent>>>,
    missed_events: Arc<Mutex<Vec<Event<GenEvent>>>>,
    model: ModelPtr<GenEvent>,
    seen: SeenPtr<EventId>,
    p2p: net::P2pPtr,
}

#[async_trait]
impl RequestHandler for JsonRpcInterface {
    async fn handle_request(&self, req: JsonRequest) -> JsonResult {
        if !req.params.is_array() {
            return JsonError::new(ErrorCode::InvalidParams, None, req.id).into()
        }

        match req.method.as_str() {
            Some("add") => self.add(req.id, req.params).await,
            Some("list") => self.list(req.id, req.params).await,
            Some("ping") => self.pong(req.id, req.params).await,
            Some("get_info") => self.get_info(req.id, req.params).await,
            Some(_) | None => return JsonError::new(ErrorCode::MethodNotFound, None, req.id).into(),
        }
    }
}

impl JsonRpcInterface {
    pub fn new(
        _nickname: String,
        unread_events: Arc<Mutex<UnreadEvents<GenEvent>>>,
        missed_events: Arc<Mutex<Vec<Event<GenEvent>>>>,
        model: ModelPtr<GenEvent>,
        seen: SeenPtr<EventId>,
        p2p: net::P2pPtr,
    ) -> Self {
        Self { _nickname, unread_events, missed_events, model, seen, p2p }
    }

    // RPCAPI:
    // Replies to a ping method.
    // --> {"jsonrpc": "2.0", "method": "ping", "params": [], "id": 42}
    // <-- {"jsonrpc": "2.0", "result": "pong", "id": 42}
    async fn pong(&self, id: Value, _params: Value) -> JsonResult {
        JsonResponse::new(json!("pong"), id).into()
    }

    // RPCAPI:
    // Retrieves P2P network information.
    // --> {"jsonrpc": "2.0", "method": "get_info", "params": [], "id": 42}
    // <-- {"jsonrpc": "2.0", result": {"nodeID": [], "nodeinfo": [], "id": 42}
    async fn get_info(&self, id: Value, _params: Value) -> JsonResult {
        let resp = self.p2p.get_info().await;
        JsonResponse::new(resp, id).into()
    }

    // RPCAPI:
    // Add a new event
    // --> {"jsonrpc": "2.0", "method": "add", "params": [], "id": 1}
    // <-- {"jsonrpc": "2.0", "result": [nickname, ...], "id": 1}
    async fn add(&self, id: Value, params: Value) -> JsonResult {
        let genevent = GenEvent {
            nick: params[0].get("nick").unwrap().to_string(),
            title: params[0].get("title").unwrap().to_string(),
            text: params[0].get("text").unwrap().to_string(),
        };

        let event = Event {
            previous_event_hash: self.model.lock().await.get_head_hash(),
            action: genevent,
            timestamp: get_current_time(),
            read_confirms: 0,
        };

        if !self.seen.push(&event.hash()).await {
            let json = json!(false);
            return JsonResponse::new(json, id).into()
        }

        self.unread_events.lock().await.insert(&event);

        self.p2p.broadcast(event).await.unwrap();

        let json = json!(true);
        JsonResponse::new(json, id).into()
    }

    // RPCAPI:
    // List events
    // --> {"jsonrpc": "2.0", "method": "list", "params": [], "id": 1}
    // <-- {"jsonrpc": "2.0", "result": [task_id, ...], "id": 1}
    async fn list(&self, id: Value, _params: Value) -> JsonResult {
        debug!("fetching all events");
        let msd = self.missed_events.lock().await.clone();

        let ser = darkfi_serial::serialize(&msd);

        let json = json!(ser);
        JsonResponse::new(json, id).into()
    }
}
