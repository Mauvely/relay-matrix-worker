// SPDX-License-Identifier: AGPL-3.0-or-later
use futures_util::FutureExt;
use ruma_common::{
    OwnedUserId,
    push::{NewPushRule, PushConditionPowerLevelsCtx, PushConditionRoomCtx, RuleKind, Ruleset},
    room_version_rules::{RoomPowerLevelsRules, RoomVersionRules},
    serde::Raw,
};
use serde_json::{Value, from_value, to_string};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn default_push_rules(user: &str) -> Result<String, String> {
    to_string(&Ruleset::server_default(
        &OwnedUserId::try_from(user).map_err(err)?,
    ))
    .map_err(err)
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[wasm_bindgen]
pub fn push_actions(
    rules: &str,
    event: &str,
    room: &str,
    user: &str,
    display: &str,
    members: u32,
    powers: &str,
) -> Result<String, String> {
    let rules: Ruleset = serde_json::from_str(rules).map_err(err)?;
    let raw = Raw::<Value>::from_json_string(event.to_owned()).map_err(err)?;
    let mut ctx = PushConditionRoomCtx::new(
        room.try_into().map_err(err)?,
        members.into(),
        user.try_into().map_err(err)?,
        display.to_owned(),
    );
    let p: Value = serde_json::from_str(powers).map_err(err)?;
    ctx.power_levels = Some(PushConditionPowerLevelsCtx::new(
        from_value(p["users"].clone()).unwrap_or_default(),
        from_value(p["users_default"].clone()).unwrap_or_default(),
        from_value(p["notifications"].clone()).unwrap_or_default(),
        RoomPowerLevelsRules::new(&RoomVersionRules::V11.authorization, []),
    ));
    // v10/v11 use no asynchronous thread-subscription condition.
    let actions = rules
        .get_actions(&raw, &ctx)
        .now_or_never()
        .ok_or("unavailable push condition")?;
    to_string(actions).map_err(err)
}

#[wasm_bindgen]
pub fn change_push_rule(
    rules: &str,
    kind: &str,
    id: &str,
    operation: &str,
    data: &str,
    after: Option<String>,
    before: Option<String>,
) -> Result<String, String> {
    let mut rules: Ruleset = serde_json::from_str(rules).map_err(err)?;
    let kind = RuleKind::from(kind);
    let mut body: Value = serde_json::from_str(data).map_err(err)?;
    match operation {
        "enabled" => rules
            .set_enabled(
                kind,
                id,
                body["enabled"].as_bool().ok_or("Expected enabled")?,
            )
            .map_err(err)?,
        "actions" => rules
            .set_actions(kind, id, from_value(body["actions"].clone()).map_err(err)?)
            .map_err(err)?,
        "delete" => rules.remove(kind, id).map_err(err)?,
        "insert" => {
            body["rule_id"] = Value::String(id.to_owned());
            let rule = match kind {
                RuleKind::Override => NewPushRule::Override(from_value(body).map_err(err)?),
                RuleKind::Content => NewPushRule::Content(from_value(body).map_err(err)?),
                RuleKind::Room => NewPushRule::Room(from_value(body).map_err(err)?),
                RuleKind::Sender => NewPushRule::Sender(from_value(body).map_err(err)?),
                RuleKind::Underride => NewPushRule::Underride(from_value(body).map_err(err)?),
                _ => return Err("Unknown rule kind".into()),
            };
            rules
                .insert(rule, after.as_deref(), before.as_deref())
                .map_err(err)?;
        }
        _ => return Err("Unknown operation".into()),
    }
    to_string(&rules).map_err(err)
}
