//! Actor-grantable capabilities from the invocation capability registry v2.
//! A grant does not establish that an invocation profile is supported or enabled.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InvocationCapability {
    CallResultDisclosure,
    GasEstimateDisclosure,
    AccessListDisclosure,
    UnsignedTransactionPreparation,
    SignedTransactionSubmission,
    OperationStatusDisclosure,
    MultiCallSimulationDisclosure,
}

impl InvocationCapability {
    /// Exact transport mappings from rpc_invocation_capability_registry_v2.
    /// Resolving a mapping does not grant its capability or enable its form.
    pub fn for_method(method: &str) -> Option<Self> {
        Some(match method {
            "eth_call" => Self::CallResultDisclosure,
            "eth_estimateGas" => Self::GasEstimateDisclosure,
            "eth_createAccessList" => Self::AccessListDisclosure,
            "pc_prepareTransaction" => Self::UnsignedTransactionPreparation,
            "eth_sendRawTransaction" => Self::SignedTransactionSubmission,
            "pc_getOperationStatus" => Self::OperationStatusDisclosure,
            "eth_simulateV1" => Self::MultiCallSimulationDisclosure,
            _ => return None,
        })
    }
    pub fn registry_id(self) -> &'static str {
        match self {
            Self::CallResultDisclosure => "CALL_RESULT_DISCLOSURE",
            Self::GasEstimateDisclosure => "GAS_ESTIMATE_DISCLOSURE",
            Self::AccessListDisclosure => "ACCESS_LIST_DISCLOSURE",
            Self::UnsignedTransactionPreparation => "UNSIGNED_TRANSACTION_PREPARATION",
            Self::SignedTransactionSubmission => "SIGNED_TRANSACTION_SUBMISSION",
            Self::OperationStatusDisclosure => "OPERATION_STATUS_DISCLOSURE",
            Self::MultiCallSimulationDisclosure => "MULTI_CALL_SIMULATION_DISCLOSURE",
        }
    }
    pub fn request_form(self) -> &'static str {
        match self {
            Self::CallResultDisclosure => "R1B_SINGLE_CONTRACT_CALL_V2",
            Self::GasEstimateDisclosure => "R1B_SINGLE_CONTRACT_ESTIMATE_V2",
            Self::AccessListDisclosure => "R1B_SINGLE_CONTRACT_ACCESS_LIST_V2",
            Self::UnsignedTransactionPreparation => "R1B_UNSIGNED_CONTRACT_TRANSACTION_V2",
            Self::SignedTransactionSubmission => "R1B_SIGNED_CONTRACT_TRANSACTION_V2",
            Self::OperationStatusDisclosure => "R1B_OWNED_OPERATION_STATUS_V2",
            Self::MultiCallSimulationDisclosure => "DEFERRED_MULTI_CALL_SIMULATION_V2",
        }
    }
    pub fn from_registry_id(id: &str) -> Option<Self> {
        Some(match id {
            "CALL_RESULT_DISCLOSURE" => Self::CallResultDisclosure,
            "GAS_ESTIMATE_DISCLOSURE" => Self::GasEstimateDisclosure,
            "ACCESS_LIST_DISCLOSURE" => Self::AccessListDisclosure,
            "UNSIGNED_TRANSACTION_PREPARATION" => Self::UnsignedTransactionPreparation,
            "SIGNED_TRANSACTION_SUBMISSION" => Self::SignedTransactionSubmission,
            "OPERATION_STATUS_DISCLOSURE" => Self::OperationStatusDisclosure,
            "MULTI_CALL_SIMULATION_DISCLOSURE" => Self::MultiCallSimulationDisclosure,
            _ => return None,
        })
    }
}
