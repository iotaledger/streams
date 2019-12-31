use crate::spongos::{self, Spongos};
use crate::trits::{Trits};

/// Type of message links.
pub enum Link {

    /// Link to a message within the current application instance, ie. `msgid` only, 81 trits.
    Relative(Trits),

    /// Absolute link to a message in another application instance: `appinst` + `msgid`, 243 + 81 trits.
    Absolute(Trits, Trits),

    /// Application-specific link/reference/identifier/URL.
    Universal(Trits),
}

