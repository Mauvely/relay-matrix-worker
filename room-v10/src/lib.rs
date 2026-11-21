// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline replay of a complete, topologically ordered v10 room trace.
//! The caller supplies trusted public keys separately from the signed PDUs.
use std::collections::{BTreeSet, HashMap};
use ruma_common::{CanonicalJsonObject, MilliSecondsSinceUnixEpoch, OwnedEventId, OwnedRoomId,
    OwnedUserId, RoomId, UserId, room_version_rules::RoomVersionRules};
use ruma_events::{StateEventType, TimelineEventType};
use ruma_signatures::{PublicKeyMap, Verified};
use ruma_state_res::{Event, StateMap, utils::event_id_set::EventIdSet};
use serde::Deserialize;
use serde_json::value::RawValue;
use wasm_bindgen::prelude::*;

#[derive(Clone, Deserialize)]
struct Pdu {
    event_id: OwnedEventId,
    room_id: OwnedRoomId,
    sender: OwnedUserId,
    origin_server_ts: MilliSecondsSinceUnixEpoch,
    #[serde(rename = "type")]
    kind: TimelineEventType,
    content: Box<RawValue>,
    state_key: Option<String>,
    prev_events: Vec<OwnedEventId>,
    auth_events: Vec<OwnedEventId>,
    redacts: Option<OwnedEventId>,
}
impl Event for Pdu {
    type Id = OwnedEventId;
    fn event_id(&self) -> &Self::Id { &self.event_id }
    fn room_id(&self) -> Option<&RoomId> { Some(&self.room_id) }
    fn sender(&self) -> &UserId { &self.sender }
    fn origin_server_ts(&self) -> MilliSecondsSinceUnixEpoch { self.origin_server_ts }
    fn event_type(&self) -> &TimelineEventType { &self.kind }
    fn content(&self) -> &RawValue { &self.content }
    fn state_key(&self) -> Option<&str> { self.state_key.as_deref() }
    fn prev_events(&self) -> Box<dyn DoubleEndedIterator<Item=&Self::Id> + '_> { Box::new(self.prev_events.iter()) }
    fn auth_events(&self) -> Box<dyn DoubleEndedIterator<Item=&Self::Id> + '_> { Box::new(self.auth_events.iter()) }
    fn redacts(&self) -> Option<&Self::Id> { self.redacts.as_ref() }
    fn rejected(&self) -> bool { false }
}
const RULES: RoomVersionRules = RoomVersionRules::V10;
type State = StateMap<OwnedEventId>;

#[derive(Default)]
struct Trace {
    events: HashMap<OwnedEventId, Pdu>,
    states: HashMap<OwnedEventId, State>,
    tips: BTreeSet<OwnedEventId>,
}
impl Trace {
    fn state_at<'a>(&self, tips: impl Iterator<Item=&'a OwnedEventId>) -> Result<State,String> {
        let states: Vec<_> = tips.map(|id| self.states.get(id).ok_or_else(|| format!("missing predecessor {id}")))
            .collect::<Result<_,_>>()?;
        if states.len() <= 1 { return Ok(states.first().map_or_else(State::new, |s| (*s).clone())); }
        let chains = states.iter().map(|state| {
            let mut chain = EventIdSet::new();
            let mut pending: Vec<_> = state.values().collect();
            while let Some(id) = pending.pop() {
                for auth in &self.events[id].auth_events {
                    if chain.insert(auth.clone()) { pending.push(auth); }
                }
            }
            chain
        }).collect();
        ruma_state_res::resolve(&RULES.authorization, RULES.state_res.v2_rules().unwrap(),
            states, chains, |id| self.events.get(id), |_| None).map_err(|e| e.to_string())
    }
    fn apply(&mut self, obj: CanonicalJsonObject, keys: &PublicKeyMap) -> Result<(),String> {
        ruma_state_res::check_pdu_format(&obj, &RULES.event_format)?;
        if ruma_signatures::verify_event(keys, &obj, &RULES).map_err(|e| e.to_string())? != Verified::All {
            return Err("trace requires original content, not redacted history".into());
        }
        let hash = ruma_signatures::reference_hash(&obj, &RULES).map_err(|e| e.to_string())?;
        let mut value = serde_json::to_value(obj).map_err(|e| e.to_string())?;
        value["event_id"] = format!("${hash}").into();
        let p: Pdu = serde_json::from_value(value).map_err(|e| e.to_string())?;
        if self.events.values().next().is_some_and(|first| first.room_id != p.room_id) { return Err("mixed room IDs".into()); }
        if self.events.contains_key(&p.event_id) { return Ok(()); }
        if p.prev_events.is_empty() && !self.events.is_empty() { return Err("second room root".into()); }
        if p.kind == TimelineEventType::RoomCreate {
            let content: serde_json::Value = serde_json::from_str(p.content.get()).map_err(|e| e.to_string())?;
            if content["room_version"] != "10" { return Err("requires room version 10".into()); }
        }
        ruma_state_res::check_state_independent_auth_rules(&RULES.authorization, &p, |id| self.events.get(id))?;
        let mut state = self.state_at(p.prev_events.iter())?;
        let mut declared = State::new();
        for id in &p.auth_events {
            let auth = self.events.get(id).ok_or_else(|| format!("missing auth event {id}"))?;
            let key = auth.state_key.clone().ok_or("auth event has no state key")?;
            declared.insert((StateEventType::from(auth.kind.to_string()), key),id.clone());
        }
        for snapshot in [&declared, &state] {
            ruma_state_res::check_state_dependent_auth_rules(&RULES.authorization, &p, |ty,key| {
                snapshot.get(&(ty.clone(),key.into())).and_then(|id| self.events.get(id))
            })?;
        }
        if let Some(key) = &p.state_key { state.insert((StateEventType::from(p.kind.to_string()),key.clone()),p.event_id.clone()); }
        for id in &p.prev_events { self.tips.remove(id); }
        self.tips.insert(p.event_id.clone());
        self.states.insert(p.event_id.clone(),state);
        self.events.insert(p.event_id.clone(),p);
        Ok(())
    }
}

#[wasm_bindgen]
pub fn replay(events: &str, keys: &str) -> Result<String,String> {
    let pdus: Vec<CanonicalJsonObject> = serde_json::from_str(events).map_err(|e| e.to_string())?;
    let keys = serde_json::from_str(keys).map_err(|e| e.to_string())?;
    let mut trace = Trace::default();
    for pdu in pdus { trace.apply(pdu, &keys)?; }
    let state = trace.state_at(trace.tips.iter())?;
    let mut result: Vec<_> = state.into_iter().map(|((kind,key),id)| (kind.to_string(),key,id)).collect();
    result.sort();
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

// Use the same v10 rules for producing live events as for verifying received PDUs.
#[wasm_bindgen]
pub fn prepare_event(event: &str) -> Result<String,String> {
    let mut obj: CanonicalJsonObject = serde_json::from_str(event).map_err(|e| e.to_string())?;
    let digest = ruma_signatures::content_hash(&obj).map_err(|e| e.to_string())?.encode();
    obj.insert("hashes".into(), CanonicalJsonObject::from([("sha256".into(), digest.clone().into())]).into());
    let mut redacted = ruma_common::canonical_json::redact(obj, &RULES.redaction, None).map_err(|e| e.to_string())?;
    redacted.remove("signatures");
    redacted.remove("unsigned");
    serde_json::to_string(&(digest,serde_json::to_string(&redacted).map_err(|e| e.to_string())?)).map_err(|e| e.to_string())
}

#[wasm_bindgen]
pub fn reference_id(event: &str) -> Result<String,String> {
    let obj = serde_json::from_str(event).map_err(|e| e.to_string())?;
    Ok(format!("${}", ruma_signatures::reference_hash(&obj, &RULES).map_err(|e| e.to_string())?))
}

#[wasm_bindgen]
pub fn auth_fields(kind: &str, sender: &str, state_key: Option<String>, content: &str) -> Result<String,String> {
    let sender = UserId::parse(sender).map_err(|e| e.to_string())?;
    let raw = RawValue::from_string(content.to_owned()).map_err(|e| e.to_string())?;
    let fields = ruma_state_res::auth_types_for_event(&kind.into(), &sender, state_key.as_deref(), &raw, &RULES.authorization)?;
    serde_json::to_string(&fields).map_err(|e| e.to_string())
}

#[wasm_bindgen]
pub fn check_current(event: &str, state: &str) -> Result<(),String> {
    let pdu: Pdu = serde_json::from_str(event).map_err(|e| e.to_string())?;
    let entries: Vec<Pdu> = serde_json::from_str(state).map_err(|e| e.to_string())?;
    ruma_state_res::check_state_dependent_auth_rules(&RULES.authorization, &pdu, |ty,key| {
        entries.iter().find(|p| p.kind.to_string() == ty.to_string() && p.state_key.as_deref() == Some(key))
    })
}

#[wasm_bindgen]
pub fn verify_signed_pdu(event: &str, keys: &str) -> Result<(),String> {
    let event = serde_json::from_str(event).map_err(|e| e.to_string())?;
    let keys = serde_json::from_str(keys).map_err(|e| e.to_string())?;
    ruma_state_res::check_pdu_format(&event, &RULES.event_format)?;
    if ruma_signatures::verify_event(&keys,&event,&RULES).map_err(|e| e.to_string())? != Verified::All {
        return Err("PDU content hash mismatch".into());
    }
    Ok(())
}

// The sole predecessor of a linear append has the room's already-committed state.
// Use the same PDU verifier and both auth checks as replay, with that trusted prefix.
#[wasm_bindgen]
pub fn check_linear(event: &str, keys: &str, predecessor: &str, state: &str, auth: &str) -> Result<(), String> {
    let obj: CanonicalJsonObject = serde_json::from_str(event).map_err(|e| e.to_string())?;
    let keys = serde_json::from_str(keys).map_err(|e| e.to_string())?;
    let predecessor = ruma_common::EventId::parse(predecessor).map_err(|e| e.to_string())?;
    let entries: Vec<Pdu> = serde_json::from_str(state).map_err(|e| e.to_string())?;
    let declared: Vec<Pdu> = serde_json::from_str(auth).map_err(|e| e.to_string())?;
    let mut trace = Trace::default();
    let mut snapshot = State::new();
    for p in entries {
        let key = p.state_key.clone().ok_or("invalid state checkpoint")?;
        snapshot.insert((StateEventType::from(p.kind.to_string()), key), p.event_id.clone());
        trace.events.insert(p.event_id.clone(), p);
    }
    for p in declared { trace.events.insert(p.event_id.clone(), p); }
    trace.states.insert(predecessor, snapshot);
    trace.apply(obj, &keys)
}
