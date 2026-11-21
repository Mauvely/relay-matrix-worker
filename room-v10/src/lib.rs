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
