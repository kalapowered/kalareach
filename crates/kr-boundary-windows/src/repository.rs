//! What the broker reads of a repository before it starts Git: the configuration listing, the
//! attributes files and `HEAD`. Each reader takes bytes and nothing else, so it runs the same
//! everywhere, and each refuses by naming a rule.

pub mod attributes;
pub mod head;
