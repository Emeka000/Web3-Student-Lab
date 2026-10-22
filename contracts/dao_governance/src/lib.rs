//! # DAO Governance Module with Quadratic Voting
//!
//! Closes issue #717.
//!
//! A Soroban-native DAO where any token holder can:
//!  - create proposals with a configurable voting window,
//!  - cast votes whose *cost* scales quadratically (cost = votes²),
//!    so large stakeholders cannot dominate by raw token weight,
//!  - finalize proposals once the deadline passes,
//!  - execute passed proposals (hook for downstream actions).
//!
//! ## Quadratic voting mechanics
//! Each voter is allocated `voice_credits` upon joining.  Casting `v` votes
//! on a proposal costs `v²` credits, forcing voters to spread influence
//! across multiple proposals rather than concentrating on one.

#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error, symbol_short, Address, Env, String,
};

// ── Types ─────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalStatus {
    Active,
    Passed,
    Failed,
    Executed,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub id: u64,
    pub creator: Address,
    pub title: String,
    pub description: String,
    pub deadline: u64,
    pub status: ProposalStatus,
    /// Net vote tally (positive = support, negative = against).
    pub tally: i128,
    /// Total voice-credits spent across all voters on this proposal.
    pub credits_spent: u128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredProposal {
    creator: Address,
    title: String,
    description: String,
    deadline: u64,
    status: u32,
    tally: i128,
    credits_spent: u128,
}

impl StoredProposal {
    fn from_proposal(proposal: &Proposal) -> Self {
        Self {
            creator: proposal.creator.clone(),
            title: proposal.title.clone(),
            description: proposal.description.clone(),
            deadline: proposal.deadline,
            status: match proposal.status {
                ProposalStatus::Active => 0,
                ProposalStatus::Passed => 1,
                ProposalStatus::Failed => 2,
                ProposalStatus::Executed => 3,
            },
            tally: proposal.tally,
            credits_spent: proposal.credits_spent,
        }
    }

    fn into_proposal(self, id: u64) -> Proposal {
        Proposal {
            id,
            creator: self.creator,
            title: self.title,
            description: self.description,
            deadline: self.deadline,
            status: match self.status {
                0 => ProposalStatus::Active,
                1 => ProposalStatus::Passed,
                2 => ProposalStatus::Failed,
                _ => panic!("invalid compact proposal status"),
            },
            tally: self.tally,
            credits_spent: self.credits_spent,
        }
    }
}

#[contracttype]
#[derive(Clone)]
pub enum Key {
    Admin,
    NextId,
    Credits(Address),
    Proposal(u64),
    CompactProposal(u64),
    Vote(u64, Address),
    UsedNonce(Address, u64),
}

pub mod ragequit;
pub mod treasury;

use ragequit::Ragequit;
use treasury::{Treasury, TreasuryState};

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DaoError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    ProposalNotFound = 4,
    ProposalClosed = 5,
    VotingDeadlineLive = 6,
    AlreadyVoted = 7,
    InsufficientCredits = 8,
    ZeroVotes = 9,
    InvalidDeadline = 10,
    ZeroShares = 11,
    ProposalNotPassed = 12,
    YesVoterCannotRagequit = 13,
    InsufficientShares = 14,
    InsufficientReserves = 15,
}
pub mod errors;

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct DaoGovernance;

#[contractimpl]
impl DaoGovernance {
    /// Initialise the DAO.  Must be called exactly once.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&Key::Admin) {
            panic_with_error!(&env, DaoError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&Key::Admin, &admin);
        env.storage().instance().set(&Key::NextId, &0u64);
    }

    /// Grant `credits` voice-credits to `member`.  Admin only.
    pub fn grant_credits(env: Env, member: Address, credits: u128) {
        Self::only_admin(&env);
        let key = Key::Credits(member.clone());
        let prev: u128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(prev + credits));
        env.events()
            .publish((symbol_short!("credits"),), (member, credits));
    }

    /// Create a new proposal.  Returns the proposal ID.
    ///
    /// * `duration` – voting window in seconds.
    pub fn create_proposal(
        env: Env,
        creator: Address,
        title: String,
        description: String,
        duration: u64,
    ) -> u64 {
        creator.require_auth();
        if duration == 0 {
            panic_with_error!(&env, DaoError::InvalidDeadline);
        }
        let id: u64 = env.storage().instance().get(&Key::NextId).unwrap_or(0);
        env.storage().instance().set(&Key::NextId, &(id + 1));

        let proposal = Proposal {
            id,
            creator: creator.clone(),
            title,
            description,
            deadline: env.ledger().timestamp() + duration,
            status: ProposalStatus::Active,
            tally: 0,
            credits_spent: 0,
        };
        Self::store_proposal(&env, &proposal);
        env.events()
            .publish((symbol_short!("propose"),), (creator, id));
        id
    }

    /// Cast `votes` on proposal `id`.
    ///
    /// * Positive = support, negative = against.
    /// * Cost = votes² credits (quadratic scaling).
    /// * Each address may vote at most once per proposal.
    /// Cast `votes` on proposal `id`.
    ///
    /// * Positive = support, negative = against.
    /// * Cost = votes² credits (quadratic scaling).
    /// * Each address may vote at most once per proposal.
    pub fn vote(env: Env, voter: Address, proposal_id: u64, votes: i64) {
        voter.require_auth();
        Self::internal_vote(&env, voter, proposal_id, votes);
    }

    /// Cast votes with SEP-0010 Web Auth nonce tracking to prevent replay across web clients.
    pub fn vote_sep0010(
        env: Env,
        voter: Address,
        proposal_id: u64,
        votes: i64,
        nonce: u64,
        _home_domain: String,
    ) {
        voter.require_auth();
        let nonce_key = Key::UsedNonce(voter.clone(), nonce);
        if env.storage().persistent().has(&nonce_key) {
            panic_with_error!(&env, DaoError::AlreadyVoted);
        }
        env.storage().persistent().set(&nonce_key, &true);
        Self::internal_vote(&env, voter, proposal_id, votes);
    }

    fn internal_vote(env: &Env, voter: Address, proposal_id: u64, votes: i64) {
        if votes == 0 {
            panic_with_error!(env, DaoError::ZeroVotes);
        }

        let mut proposal = load_proposal(env, proposal_id)
            .unwrap_or_else(|| panic_with_error!(env, DaoError::ProposalNotFound));

        if proposal.status != ProposalStatus::Active || env.ledger().timestamp() > proposal.deadline
        {
            panic_with_error!(env, DaoError::ProposalClosed);
        }

        let vote_key = Key::Vote(proposal_id, voter.clone());
        if env.storage().persistent().has(&vote_key) {
            panic_with_error!(env, DaoError::AlreadyVoted);
        }

        // Quadratic cost: cost = |votes|²
        let abs_v = votes.unsigned_abs() as u128;
        let cost: u128 = abs_v.saturating_mul(abs_v);

        let credits_key = Key::Credits(voter.clone());
        let bal: u128 = env.storage().persistent().get(&credits_key).unwrap_or(0);
        if bal < cost {
            panic_with_error!(env, DaoError::InsufficientCredits);
        }
        env.storage().persistent().set(&credits_key, &(bal - cost));

        proposal.tally += votes as i128;
        proposal.credits_spent = proposal.credits_spent.saturating_add(cost);
        Self::store_proposal(env, &proposal);
        env.storage().persistent().set(&vote_key, &votes);

        env.events()
            .publish((symbol_short!("vote"),), (voter, proposal_id, votes, cost));
    }

    /// Finalize a proposal after its deadline.  Anyone may call this.
    pub fn finalize(env: Env, proposal_id: u64) {
        let mut proposal = load_proposal(&env, proposal_id)
            .unwrap_or_else(|| panic_with_error!(&env, DaoError::ProposalNotFound));

        if proposal.status != ProposalStatus::Active {
            panic_with_error!(&env, DaoError::ProposalClosed);
        }
        if env.ledger().timestamp() <= proposal.deadline {
            panic_with_error!(&env, DaoError::VotingDeadlineLive);
        }

        proposal.status = if proposal.tally > 0 {
            ProposalStatus::Passed
        } else {
            ProposalStatus::Failed
        };
        Self::store_proposal(&env, &proposal);
        env.events()
            .publish((symbol_short!("finalize"),), (proposal_id, proposal.tally));
    }

    /// Mark a passed proposal as executed.  Admin only.
    pub fn execute(env: Env, caller: Address, proposal_id: u64) {
        Self::only_admin(&env);
        caller.require_auth();

        let mut proposal = load_proposal(&env, proposal_id)
            .unwrap_or_else(|| panic_with_error!(&env, DaoError::ProposalNotFound));

        if proposal.status != ProposalStatus::Passed {
            panic_with_error!(&env, DaoError::ProposalClosed);
        }
        proposal.status = ProposalStatus::Executed;
        Self::store_proposal(&env, &proposal);
        env.events()
            .publish((symbol_short!("execute"),), (caller, proposal_id));
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    pub fn get_proposal(env: Env, id: u64) -> Option<Proposal> {
        load_proposal(&env, id)
    }

    pub fn credits_of(env: Env, member: Address) -> u128 {
        env.storage()
            .persistent()
            .get(&Key::Credits(member))
            .unwrap_or(0)
    }

    pub fn vote_of(env: Env, proposal_id: u64, voter: Address) -> Option<i64> {
        env.storage()
            .persistent()
            .get(&Key::Vote(proposal_id, voter))
    }

    // ── Treasury & Ragequit (SC-042) ──────────────────────────────────────────

    pub fn deposit_treasury(env: Env, caller: Address, amount: u128) {
        caller.require_auth();
        Treasury::deposit_reserves(&env, amount);
        env.events()
            .publish((symbol_short!("tres_dep"),), (caller, amount));
    }

    pub fn grant_shares(env: Env, member: Address, shares: u128) {
        Self::only_admin(&env);
        let current = Treasury::get_shares(&env, &member);
        Treasury::set_shares(&env, &member, current.saturating_add(shares));
        env.events()
            .publish((symbol_short!("sh_grant"),), (member, shares));
    }

    pub fn treasury_shares_of(env: Env, member: Address) -> u128 {
        Treasury::get_shares(&env, &member)
    }

    pub fn get_treasury_state(env: Env) -> TreasuryState {
        Treasury::get_state(&env)
    }

    pub fn ragequit(env: Env, voter: Address, proposal_id: u64, shares_to_burn: u128) -> u128 {
        let payout = Ragequit::execute_ragequit(&env, voter.clone(), proposal_id, shares_to_burn);
        env.events().publish(
            (symbol_short!("ragequit"),),
            (voter, proposal_id, shares_to_burn, payout),
        );
        payout
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    fn only_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&Key::Admin)
            .unwrap_or_else(|| panic_with_error!(env, DaoError::NotInitialized));
        admin.require_auth();
    }

    fn store_proposal(env: &Env, proposal: &Proposal) {
        env.storage().persistent().set(
            &Key::CompactProposal(proposal.id),
            &StoredProposal::from_proposal(proposal),
        );
        env.storage()
            .persistent()
            .remove(&Key::Proposal(proposal.id));
    }
}

pub(crate) fn load_proposal(env: &Env, id: u64) -> Option<Proposal> {
    if let Some(proposal) = env
        .storage()
        .persistent()
        .get::<Key, StoredProposal>(&Key::CompactProposal(id))
    {
        return Some(proposal.into_proposal(id));
    }
    env.storage().persistent().get(&Key::Proposal(id))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger as _},
        Env, String,
    };

    fn setup() -> (Env, DaoGovernanceClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register(DaoGovernance, ());
        let client = DaoGovernanceClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, client, admin)
    }

    #[test]
    fn quadratic_cost_deducted_correctly() {
        let (env, client, admin) = setup();
        let voter = Address::generate(&env);
        client.grant_credits(&voter, &100u128);

        let pid = client.create_proposal(
            &admin,
            &String::from_str(&env, "Test"),
            &String::from_str(&env, "Desc"),
            &3600,
        );

        // 3 votes → cost = 9
        client.vote(&voter, &pid, &3i64);
        assert_eq!(client.credits_of(&voter), 91);

        let p = client.get_proposal(&pid).unwrap();
        assert_eq!(p.tally, 3);
        assert_eq!(p.credits_spent, 9);
    }

    #[test]
    fn proposal_passes_when_tally_positive() {
        let (env, client, admin) = setup();
        let voter = Address::generate(&env);
        client.grant_credits(&voter, &1_000u128);

        let pid = client.create_proposal(
            &admin,
            &String::from_str(&env, "Upgrade"),
            &String::from_str(&env, "Details"),
            &100,
        );
        client.vote(&voter, &pid, &5i64);

        env.ledger().with_mut(|l| l.timestamp += 200);
        client.finalize(&pid);

        assert_eq!(
            client.get_proposal(&pid).unwrap().status,
            ProposalStatus::Passed
        );
    }

    #[test]
    fn proposal_fails_when_tally_non_positive() {
        let (env, client, admin) = setup();
        let voter = Address::generate(&env);
        client.grant_credits(&voter, &1_000u128);

        let pid = client.create_proposal(
            &admin,
            &String::from_str(&env, "Bad idea"),
            &String::from_str(&env, "No"),
            &100,
        );
        client.vote(&voter, &pid, &-4i64);

        env.ledger().with_mut(|l| l.timestamp += 200);
        client.finalize(&pid);

        assert_eq!(
            client.get_proposal(&pid).unwrap().status,
            ProposalStatus::Failed
        );
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #407)")]
    fn cannot_vote_twice() {
        let (env, client, admin) = setup();
        let voter = Address::generate(&env);
        client.grant_credits(&voter, &1_000u128);

        let pid = client.create_proposal(
            &admin,
            &String::from_str(&env, "D"),
            &String::from_str(&env, "D"),
            &3600,
        );
        client.vote(&voter, &pid, &1i64);
        client.vote(&voter, &pid, &1i64); // panic
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #408)")]
    fn insufficient_credits_rejected() {
        let (env, client, admin) = setup();
        let voter = Address::generate(&env);
        client.grant_credits(&voter, &3u128); // only 3 credits

        let pid = client.create_proposal(
            &admin,
            &String::from_str(&env, "Big"),
            &String::from_str(&env, "Big"),
            &3600,
        );
        client.vote(&voter, &pid, &5i64); // cost = 25 > 3 → panic
    }

    #[test]
    fn test_ragequit_dissenting_voter_burns_shares_and_receives_pro_rata() {
        let (env, client, admin) = setup();
        let voter_no = Address::generate(&env);
        let voter_yes = Address::generate(&env);

        client.grant_credits(&voter_no, &1_000u128);
        client.grant_credits(&voter_yes, &1_000u128);

        // Setup treasury: 1000 shares total (400 for voter_no, 600 for voter_yes), 50,000 reserves
        client.grant_shares(&voter_no, &400u128);
        client.grant_shares(&voter_yes, &600u128);
        client.deposit_treasury(&admin, &50_000u128);

        let pid = client.create_proposal(
            &admin,
            &String::from_str(&env, "Controversial proposal"),
            &String::from_str(&env, "Details"),
            &100,
        );

        // voter_no votes -2 (against), voter_yes votes +5 (for)
        client.vote(&voter_no, &pid, &-2i64);
        client.vote(&voter_yes, &pid, &5i64);

        // Proposal passes after deadline
        env.ledger().with_mut(|l| l.timestamp += 200);
        client.finalize(&pid);
        assert_eq!(
            client.get_proposal(&pid).unwrap().status,
            ProposalStatus::Passed
        );

        // voter_no ragequits before proposal is executed: burns 400 shares
        // Expected payout: 400 * 50,000 / 1000 = 20,000
        let payout = client.ragequit(&voter_no, &pid, &400u128);
        assert_eq!(payout, 20_000u128);

        // Shares burned atomically
        assert_eq!(client.treasury_shares_of(&voter_no), 0);
        let treasury = client.get_treasury_state();
        assert_eq!(treasury.total_shares, 600);
        assert_eq!(treasury.total_reserves, 30_000);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #13)")]
    fn test_ragequit_prohibits_yes_voters() {
        let (env, client, admin) = setup();
        let voter_yes = Address::generate(&env);
        client.grant_credits(&voter_yes, &1_000u128);
        client.grant_shares(&voter_yes, &500u128);
        client.deposit_treasury(&admin, &50_000u128);

        let pid = client.create_proposal(
            &admin,
            &String::from_str(&env, "P"),
            &String::from_str(&env, "D"),
            &100,
        );
        client.vote(&voter_yes, &pid, &5i64);

        env.ledger().with_mut(|l| l.timestamp += 200);
        client.finalize(&pid);

        // Should panic with YesVoterCannotRagequit (code 13)
        client.ragequit(&voter_yes, &pid, &100u128);
    }

    #[test]
    fn test_vote_sep0010_and_replay_rejection() {
        let (env, client, admin) = setup();
        let voter = Address::generate(&env);
        client.grant_credits(&voter, &100u128);

        let pid = client.create_proposal(
            &admin,
            &String::from_str(&env, "SEP10 Prop"),
            &String::from_str(&env, "Desc"),
            &3600,
        );

        let nonce = 9999u64;
        let domain = String::from_str(&env, "governance.studentlab.stellar.org");

        // Cast SEP-0010 authenticated vote
        client.vote_sep0010(&voter, &pid, &3i64, &nonce, &domain);

        let prop = client.get_proposal(&pid).unwrap();
        assert_eq!(prop.tally, 3);
        assert_eq!(client.credits_of(&voter), 100 - 9);

        // Replay attempt with same nonce is rejected
        let res = client.try_vote_sep0010(&voter, &pid, &1i64, &nonce, &domain);
        assert!(res.is_err());
    }
}

#[cfg(test)]
mod test;
