//! The ipc op names and the wire level table agree (wire dev-depends on ipc; ipc never on wire).
use saiife_ipc::msg::*;
use saiife_wire::level::{actions, level_for, Level};

#[test]
fn box_ops_match_the_table() {
    let pairs = [
        (OP_BOX_OVERVIEW, actions::BOX_OVERVIEW),
        (OP_BOX_LIST, actions::BOX_LIST),
        (OP_BOX_DIFF, actions::BOX_DIFF),
        (OP_BOX_TERM_READ, actions::BOX_TERM_READ),
        (OP_BOX_STOP, actions::BOX_STOP),
        (OP_BOX_PAUSE, actions::BOX_PAUSE),
        (OP_BOX_RESUME, actions::BOX_RESUME),
        (OP_BOX_DISCARD, actions::BOX_DISCARD),
        (OP_BOX_REORDER, actions::BOX_REORDER),
        (OP_BOX_STEER, actions::BOX_STEER),
        (OP_BOX_REVISE, actions::BOX_REVISE),
        (OP_BOX_LAND, actions::BOX_LAND),
        (OP_BOX_PUSH, actions::BOX_PUSH),
        (OP_BOX_PR, actions::BOX_PR),
        (OP_BOX_SPAWN, actions::BOX_SPAWN),
        (OP_BOX_TEMPLATES, actions::BOX_TEMPLATES),
        (OP_BOX_INBOX, actions::BOX_INBOX),
    ];
    for (op, action) in pairs {
        assert_eq!(op, action);
        assert!(
            matches!(level_for(op), Some(Level::Signed | Level::Touch)),
            "{op}"
        );
    }
}

#[test]
fn machine_side_workspace_ops_are_machine_only() {
    for op in [
        OP_WORKSPACE_PAIR_BEGIN,
        OP_WORKSPACE_PAIR_STATUS,
        OP_WORKSPACE_PAIR_CONFIRM,
        OP_WORKSPACE_DEVICES,
        OP_WORKSPACE_REVOKE,
        OP_WORKSPACE_HELLO,
        OP_WORKSPACE_PAIR_FINISH,
        OP_WORKSPACE_FRAME,
        OP_WORKSPACE_SIGN,
    ] {
        assert_eq!(level_for(op), Some(Level::MachineOnly), "{op}");
    }
}
