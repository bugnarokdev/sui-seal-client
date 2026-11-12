//! The `seal_approve*` transaction sent to key servers.

use std::str::FromStr;

use sui_sdk_types::{
    Address, Argument, Command, Identifier, Input, MoveCall, ObjectReference,
    ProgrammableTransaction, SharedInput,
};

use crate::error::{Error, Result};

/// Key servers reject PTBs with more commands than this.
const MAX_COMMANDS: usize = 100;

/// Extra argument passed to a `seal_approve*` function after the key id.
#[derive(Debug, Clone)]
pub enum ApprovalArg {
    /// BCS-encoded pure value.
    Pure(Vec<u8>),
    /// Shared object, read-only.
    Shared {
        id: Address,
        initial_shared_version: u64,
    },
    /// Immutable or owned object.
    Object(ObjectReference),
}

impl ApprovalArg {
    fn into_input(self) -> Input {
        match self {
            ApprovalArg::Pure(bytes) => Input::Pure(bytes),
            ApprovalArg::Shared {
                id,
                initial_shared_version,
            } => Input::Shared(SharedInput::new(id, initial_shared_version, false)),
            ApprovalArg::Object(r) => Input::ImmutableOrOwned(r),
        }
    }
}

/// A transaction made only of `seal_approve*` calls on one package.
///
/// Key servers dry-run it with the session's address as sender; keys are released for
/// the ids of the calls that do not abort.
#[derive(Debug, Clone)]
pub struct ApprovalTx {
    package_id: Address,
    ids: Vec<Vec<u8>>,
    ptb: ProgrammableTransaction,
}

impl ApprovalTx {
    pub fn new(package_id: Address) -> Self {
        Self {
            package_id,
            ids: Vec::new(),
            ptb: ProgrammableTransaction {
                inputs: vec![],
                commands: vec![],
            },
        }
    }

    /// Adds `package::module::function(id, args...)`. `function` must start with
    /// `seal_approve`; `id` is the inner id (without the package prefix).
    pub fn call(
        mut self,
        module: &str,
        function: &str,
        id: &[u8],
        args: Vec<ApprovalArg>,
    ) -> Result<Self> {
        if !function.starts_with("seal_approve") {
            return Err(Error::InvalidInput(format!(
                "function {function} must start with seal_approve"
            )));
        }
        if id.is_empty() {
            return Err(Error::InvalidInput("key id must not be empty".into()));
        }
        if self.ptb.commands.len() >= MAX_COMMANDS {
            return Err(Error::InvalidInput(format!(
                "at most {MAX_COMMANDS} seal_approve calls per request"
            )));
        }
        let module = Identifier::from_str(module)
            .map_err(|e| Error::InvalidInput(format!("module {module}: {e}")))?;
        let function = Identifier::from_str(function)
            .map_err(|e| Error::InvalidInput(format!("function {function}: {e}")))?;
        let mut arguments = Vec::with_capacity(args.len() + 1);
        arguments.push(self.push_input(Input::Pure(
            bcs::to_bytes(&id.to_vec()).expect("bytes serialize"),
        ))?);
        for arg in args {
            arguments.push(self.push_input(arg.into_input())?);
        }
        self.ptb.commands.push(Command::MoveCall(MoveCall {
            package: self.package_id,
            module,
            function,
            type_arguments: vec![],
            arguments,
        }));
        self.ids.push(id.to_vec());
        Ok(self)
    }

    fn push_input(&mut self, input: Input) -> Result<Argument> {
        if let Some(i) = self.ptb.inputs.iter().position(|x| *x == input) {
            return Ok(Argument::Input(i as u16));
        }
        let index = u16::try_from(self.ptb.inputs.len())
            .map_err(|_| Error::InvalidInput("too many inputs".into()))?;
        self.ptb.inputs.push(input);
        Ok(Argument::Input(index))
    }

    pub fn package_id(&self) -> Address {
        self.package_id
    }

    /// Inner ids covered by this transaction.
    pub fn ids(&self) -> &[Vec<u8>] {
        &self.ids
    }

    pub(crate) fn ptb(&self) -> &ProgrammableTransaction {
        &self.ptb
    }

    /// BCS of the `ProgrammableTransaction` (what key servers receive, base64-encoded).
    pub fn to_bcs(&self) -> Vec<u8> {
        bcs::to_bytes(&self.ptb).expect("ptb serializes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_valid_ptb_and_dedups_inputs() {
        let pkg = Address::new([1u8; 32]);
        let shared = ApprovalArg::Shared {
            id: Address::new([2u8; 32]),
            initial_shared_version: 7,
        };
        let tx = ApprovalTx::new(pkg)
            .call(
                "allowlist",
                "seal_approve",
                &[1, 2, 3],
                vec![shared.clone()],
            )
            .unwrap()
            .call("allowlist", "seal_approve", &[4, 5], vec![shared])
            .unwrap();
        assert_eq!(tx.ids(), &[vec![1, 2, 3], vec![4, 5]]);
        // Two ids + one shared object (deduplicated).
        assert_eq!(tx.ptb().inputs.len(), 3);
        assert_eq!(tx.ptb().commands.len(), 2);
        // First argument of each call is a pure vector<u8> with the id.
        let Input::Pure(first) = &tx.ptb().inputs[0] else {
            panic!()
        };
        assert_eq!(bcs::from_bytes::<Vec<u8>>(first).unwrap(), vec![1, 2, 3]);
        // Round-trips through BCS as the key server decodes it.
        let back: ProgrammableTransaction = bcs::from_bytes(&tx.to_bcs()).unwrap();
        assert_eq!(&back, tx.ptb());
    }

    #[test]
    fn rejects_bad_calls() {
        let pkg = Address::ZERO;
        assert!(
            ApprovalTx::new(pkg)
                .call("m", "approve", &[1], vec![])
                .is_err()
        );
        assert!(
            ApprovalTx::new(pkg)
                .call("m", "seal_approve", &[], vec![])
                .is_err()
        );
        assert!(
            ApprovalTx::new(pkg)
                .call("bad module", "seal_approve", &[1], vec![])
                .is_err()
        );
    }

    #[test]
    fn regression_matches_mysten_signed_request_vector() {
        // Same PTB as `test_signed_request_regression` in seal-sdk (seal-v0.6.16):
        // a MoveCall without arguments cannot be built through `call`, so check the
        // underlying BCS the same way the SDK does.
        let pkg =
            Address::from_str("0xd92bc457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d5")
                .unwrap();
        let ptb = ProgrammableTransaction {
            inputs: vec![],
            commands: vec![Command::MoveCall(MoveCall {
                package: pkg,
                module: Identifier::from_str("bla").unwrap(),
                function: Identifier::from_str("seal_approve_x").unwrap(),
                type_arguments: vec![],
                arguments: vec![],
            })],
        };
        assert_eq!(
            hex::encode(bcs::to_bytes(&ptb).unwrap()),
            "000100d92bc457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d503626c610e7365616c5f617070726f76655f780000"
        );
    }
}
