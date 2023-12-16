#![cfg_attr(not(feature = "std"), no_std)]

use concordium_cis2::*;
use concordium_std::*;

const SUPPORTS_STANDARDS: [StandardIdentifier<'static>; 2] =
    [CIS0_STANDARD_IDENTIFIER, CIS2_STANDARD_IDENTIFIER];

#[derive(Serialize, Debug, PartialEq, Eq, Reject, SchemaType)]
enum CustomContractError {
    /// Failed parsing the parameter.
    #[from(ParseError)]
    ParseParams,
    /// Failed logging: Log is full.
    LogFull,
    /// Failed logging: Log is malformed.
    LogMalformed,
    /// Invalid contract name.
    InvalidContractName,
    /// Only a smart contract can call this function.
    ContractOnly,
    /// Failed to invoke a contract.
    InvokeContractError,
    /// Trying to transfer
    ///
    TransferError,
    /// burn
    NoBalanceToBurn,
    /// event is not running
    EventPassive,
    /// only one token can be transferred
    MoreThanOneTokenTransfer,
}


type ContractTokenId = TokenIdU8;
type ContractTokenAmount = TokenAmountU64;
type ContractError = Cis2Error<CustomContractError>;
type ContractResult<A> = Result<A, ContractError>;

#[derive(Debug, Serialize, Clone, SchemaType)]
pub struct TokenMetadata {
    /// The URL following the specification RFC1738.
    #[concordium(size_length = 2)]
    pub url: String,
    /// A optional hash of the content.
    #[concordium(size_length = 2)]
    pub hash: String,
}

#[derive(Serialize, SchemaType)]
struct ViewAddressState {
    balances: Vec<(ContractTokenId, ContractTokenAmount)>,
    operators: Vec<Address>,
}

#[derive(Serialize, SchemaType)]
struct ViewState {
    state: Vec<(Address, ViewAddressState)>,
    tokens: Vec<ContractTokenId>,
    status: EventStatus,
}

impl TokenMetadata {
    fn get_hash_bytes(&self) -> Option<[u8; 32]> {
        let mut hash_bytes: [u8; 32] = Default::default();
        let hex_res = hex::decode_to_slice(self.hash.to_owned(), &mut hash_bytes);

        match hex_res {
            Ok(_) => Some(hash_bytes),
            Err(_) => Option::None,
        }
    }

    fn to_metadata_url(&self) -> MetadataUrl {
        let mut hash_bytes: [u8; 32] = Default::default();
        hex::decode_to_slice(self.hash.to_string(), &mut hash_bytes).unwrap();
        MetadataUrl {
            url: self.url.to_string(),
            hash: self.get_hash_bytes(),
        }
    }
}

impl<S: HasStateApi> AddressState<S> {
    fn empty(state_builder: &mut StateBuilder<S>) -> Self {
        AddressState {
            balances: state_builder.new_map(),
            operators: state_builder.new_set(),
        }
    }
}

#[derive(Serial, Deserial, SchemaType)]
struct MintParams {
    owner: Address,
    tokens: collections::BTreeMap<ContractTokenId, (TokenMetadata, ContractTokenAmount)>,
}

#[derive(Serialize, PartialEq, Eq, Debug, Clone, Copy, SchemaType)]
enum EventStatus {
    Active,
    Pause,
}

/// The state for each address.
#[derive(Serial, DeserialWithState, Deletable)]
#[concordium(state_parameter = "S")]
struct AddressState<S> {
    /// The amount of tokens owned by this address.
    balances: StateMap<ContractTokenId, ContractTokenAmount, S>,
    /// The address which are currently enabled as operators for this address.
    operators: StateSet<Address, S>,
}

#[derive(Serial, DeserialWithState )]
#[concordium(state_parameter = "S")]

pub struct State<S> {
     state: StateMap<Address, AddressState<S>, S>,
     tokens: StateMap<ContractTokenId, MetadataUrl, S>,
     implementors: StateMap<StandardIdentifierOwned, Vec<ContractAddress>, S>,
     event_state: EventStatus,
}

impl<S: HasStateApi> State<S> {
    fn empty(state_builder: &mut StateBuilder<S>) -> Self {
        State {
            state: state_builder.new_map(),
            tokens: state_builder.new_map(),
            implementors: state_builder.new_map(),
            event_state: EventStatus::Active,
        }
    }

    fn mint(
        &mut self,
        token_id: &ContractTokenId,
        token_metadata: &TokenMetadata,
        amount: ContractTokenAmount,
        owner: &Address,
        state_builder: &mut StateBuilder<S>,
    ) {
        self.tokens
            .insert(*token_id, token_metadata.to_metadata_url());
        let mut owner_state = self
            .state
            .entry(*owner)
            .or_insert_with(|| AddressState::empty(state_builder));
        let mut owner_balance = owner_state.balances.entry(*token_id).or_insert(0.into());
        *owner_balance += amount;
    }

      /// Check that the token ID currently exists in this contract.
      #[inline(always)]
      fn contains_token(&self, token_id: &ContractTokenId) -> bool {
          self.tokens.get(token_id).is_some()
      }

    fn balance(
        &self,
        token_id: &ContractTokenId,
        address: &Address,
    ) -> ContractResult<ContractTokenAmount> {
        ensure!(self.contains_token(token_id), ContractError::InvalidTokenId);

        let balance = self.state.get(address).map_or(0.into(), |address_state| {
            address_state
                .balances
                .get(token_id)
                .map_or(0.into(), |x| *x)
        });

        Ok(balance)
    }

    fn pause_event(&mut self) {
        self.event_state = EventStatus::Pause
    }

    fn resume_event(&mut self) {
        self.event_state = EventStatus::Pause
    }

}

/// Initialize contract instance with a no token types.
#[init(contract = "poap")]
fn contract_init<S: HasStateApi>(
    _ctx: &impl HasInitContext,
    state_builder: &mut StateBuilder<S>,
) -> InitResult<State<S>> {
    Ok(State::empty(state_builder))
}


#[receive(contract = "poap", name = "view", return_value = "ViewState")]
fn contract_view<S: HasStateApi>(
    _ctx: &impl HasReceiveContext,
    host: &impl HasHost<State<S>, StateApiType = S>,
) -> ReceiveResult<ViewState> {
    let state = host.state();
    // let status = state.event_state;

    let mut inner_state = Vec::new();
    for (k, a_state) in state.state.iter() {
        let mut balances = Vec::new();
        let mut operators = Vec::new();
        for (token_id, amount) in a_state.balances.iter() {
            balances.push((*token_id, *amount));
        }
        for o in a_state.operators.iter() {
            operators.push(*o);
        }

        inner_state.push((
            *k,
            ViewAddressState {
                balances,
                operators,
            },
        ));
    }
    let mut tokens = Vec::new();
    for v in state.tokens.iter() {
        tokens.push(v.0.to_owned());
    }

    Ok(ViewState {
        state: inner_state,
        tokens,
        status: state.event_state,
    })
}


/// Mint new tokens with a given address as the owner of these tokens.
/// Can only be called by the contract owner.
/// Logs a `Mint` and a `TokenMetadata` event for each token.
/// The url for the token metadata is the token ID encoded in hex, appended on
/// the `TOKEN_METADATA_BASE_URL`.
///
/// It rejects if:
/// - The sender is not the contract instance owner.
/// - Fails to parse parameter.
/// - Any of the tokens fails to be minted, which could be if:
///     - Fails to log Mint event.
///     - Fails to log TokenMetadata event.
///
/// Note: Can at most mint 32 token types in one call due to the limit on the
/// number of logs a smart contract can produce on each function call.
#[receive(
    contract = "poap",
    name = "mint",
    parameter = "MintParams",
    error = "ContractError",
    enable_logger,
    mutable
)]
fn contract_mint<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
    logger: &mut impl HasLogger,
) -> ContractResult<()> {
    // Get the contract owner
    let owner = ctx.owner();
    // Get the sender of the transaction
    let sender = ctx.sender();

    ensure!(sender.matches_account(&owner), ContractError::Unauthorized);

    // Parse the parameter.
    let params: MintParams = ctx.parameter_cursor().get()?;

    let (state, builder) = host.state_and_builder();

    ensure!(
        state.event_state == EventStatus::Active,
        ContractError::Custom(CustomContractError::EventPassive)
    );

    for (token_id, token_info) in params.tokens {
        // Mint the token in the state.
        state.mint(
            &token_id,
            &token_info.0,
            token_info.1,
            &params.owner,
            builder,
        );
    }
    Ok(())
}
 

/// Parameter type for the CIS-2 function `balanceOf` specialized to the subset
/// of TokenIDs used by this contract.
type ContractBalanceOfQueryParams = BalanceOfQueryParams<ContractTokenId>;

/// Response type for the CIS-2 function `balanceOf` specialized to the subset
/// of TokenAmounts used by this contract.
type ContractBalanceOfQueryResponse = BalanceOfQueryResponse<ContractTokenAmount>;

/// Get the balance of given token IDs and addresses.
///
/// It rejects if:
/// - It fails to parse the parameter.
/// - Any of the queried `token_id` does not exist.
#[receive(
    contract = "poap",
    name = "balanceOf",
    parameter = "ContractBalanceOfQueryParams",
    return_value = "ContractBalanceOfQueryResponse",
    error = "ContractError"
)]
fn contract_balance_of<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<ContractBalanceOfQueryResponse> {
    // Parse the parameter.
    let params: ContractBalanceOfQueryParams = ctx.parameter_cursor().get()?;
    // Build the response.
    let mut response = Vec::with_capacity(params.queries.len());
    for query in params.queries {
        // Query the state for balance.
        let amount = host.state().balance(&query.token_id, &query.address)?;
        response.push(amount);
    }
    let result = ContractBalanceOfQueryResponse::from(response);
    Ok(result)
}