pub mod ty;
pub mod scope;
pub mod context;
pub mod checker;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod checker_tests;

#[cfg(test)]
mod effects_tests;

#[cfg(test)]
mod capability_tests;

#[cfg(test)]
mod program_tests;

#[cfg(test)]
mod module_tests;

#[cfg(test)]
mod linearity_tests;
