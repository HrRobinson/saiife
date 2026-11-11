//! The box state machine (spec §7.7).
use saiife_wire::source::{BoxError, BoxState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Admit,
    Ready,
    Pause,
    Resume,
    Finish,
    Revise,
    Requeue,
    Stop,
    Land,
    Discard,
    BootFailed,
    VmLost,
}

/// The next state, or `WrongState { state: from }` for a blank cell.
///
/// Two deliberate departures from the spec table, per plan 28's conformance
/// kit: stop of a queued box is `wrong_state` (a queued box is cancelled with
/// `Discard`), and (R-P9) discard is valid only from Queued, Done, Landed and
/// Discarded.
pub fn transition(from: BoxState, ev: Event) -> Result<BoxState, BoxError> {
    use BoxState::*;
    use Event::*;
    let to = match (from, ev) {
        (Queued, Admit) => Starting,
        (Queued, Discard) => Discarded,

        (Starting, Ready) => Running,
        (Starting, Stop | VmLost) => Done,
        (Starting, BootFailed) => Discarded,

        (Running, Pause) => Paused,
        (Running, Finish | Stop | VmLost) => Done,

        (Paused, Resume) => Running,
        (Paused, Stop | VmLost) => Done,

        (Done, Revise) => Running,
        (Done, Requeue) => Queued,
        (Done, Stop | VmLost) => Done,
        (Done, Land) => Landed,
        (Done, Discard) => Discarded,

        (Landed, Revise) => Running,
        (Landed, Requeue) => Queued,
        (Landed, Stop | Land | VmLost) => Landed,
        (Landed, Discard) => Discarded,

        (Discarded, Stop | Discard) => Discarded,

        _ => return Err(BoxError::WrongState { state: from }),
    };
    Ok(to)
}

/// Whether a box occupies capacity: its VM is on in a live or finished state.
pub fn holds_capacity(state: BoxState, vm_on: bool) -> bool {
    vm_on
        && matches!(
            state,
            BoxState::Starting
                | BoxState::Running
                | BoxState::Paused
                | BoxState::Done
                | BoxState::Landed
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use BoxState::*;
    use Event::*;

    const STATES: [BoxState; 7] = [Queued, Starting, Running, Paused, Done, Landed, Discarded];
    const EVENTS: [Event; 12] = [
        Admit, Ready, Pause, Resume, Finish, Revise, Requeue, Stop, Land, Discard, BootFailed,
        VmLost,
    ];

    #[test]
    fn table_matches_spec() {
        // The spec table with rulings R1 (queued+stop blank) and R2 applied.
        let ok: &[(BoxState, Event, BoxState)] = &[
            (Queued, Admit, Starting),
            (Queued, Discard, Discarded),
            (Starting, Ready, Running),
            (Starting, Stop, Done),
            (Starting, BootFailed, Discarded),
            (Starting, VmLost, Done),
            (Running, Pause, Paused),
            (Running, Finish, Done),
            (Running, Stop, Done),
            (Running, VmLost, Done),
            (Paused, Resume, Running),
            (Paused, Stop, Done),
            (Paused, VmLost, Done),
            (Done, Revise, Running),
            (Done, Requeue, Queued),
            (Done, Stop, Done),
            (Done, Land, Landed),
            (Done, Discard, Discarded),
            (Done, VmLost, Done),
            (Landed, Revise, Running),
            (Landed, Requeue, Queued),
            (Landed, Stop, Landed),
            (Landed, Land, Landed),
            (Landed, Discard, Discarded),
            (Landed, VmLost, Landed),
            (Discarded, Stop, Discarded),
            (Discarded, Discard, Discarded),
        ];
        for &(from, ev, to) in ok {
            assert_eq!(transition(from, ev).unwrap(), to, "{from:?} + {ev:?}");
        }
        for from in STATES {
            for ev in EVENTS {
                if ok.iter().any(|&(f, e, _)| f == from && e == ev) {
                    continue;
                }
                assert_eq!(
                    transition(from, ev).unwrap_err(),
                    BoxError::WrongState { state: from },
                    "{from:?} + {ev:?} should be blank"
                );
            }
        }
    }

    #[test]
    fn stop_is_idempotent_on_terminal_states() {
        for s in [Done, Landed, Discarded] {
            assert_eq!(transition(s, Stop).unwrap(), s);
        }
        assert_eq!(
            transition(Queued, Stop).unwrap_err(),
            BoxError::WrongState { state: Queued }
        );
    }

    #[test]
    fn capacity_follows_vm() {
        assert!(holds_capacity(Done, true));
        assert!(!holds_capacity(Done, false));
        assert!(!holds_capacity(Queued, true));
        assert!(!holds_capacity(Discarded, true));
    }
}
